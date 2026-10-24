package grouping

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type diskPolicy struct {
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

func sealSnapshot(snapshot *Snapshot) error {
	snapshot.Digest = ""
	data, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("grouping: encode snapshot: %w", err)
	}
	digest := sha256.Sum256(data)
	snapshot.Digest = hex.EncodeToString(digest[:])
	return nil
}

func (s *Store) persist(snapshot Snapshot) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(data)
	payload, err := json.Marshal(diskPolicy{Payload: data, MAC: hex.EncodeToString(mac.Sum(nil))})
	if err != nil {
		return err
	}
	if len(payload) > 64<<20 {
		return fmt.Errorf("grouping: policy snapshot exceeds size limit")
	}
	return atomicPolicyWrite(s.dir, "policy.json", payload)
}

func (s *Store) load() error {
	key, err := readPolicyFile(filepath.Join(s.dir, "identity.key"), 32)
	if err != nil || len(key) != 32 {
		return ErrUnavailable
	}
	data, err := readPolicyFile(filepath.Join(s.dir, "policy.json"), 64<<20)
	if err != nil {
		return ErrUnavailable
	}
	var envelope diskPolicy
	if err := decodePolicyJSON(data, &envelope); err != nil {
		return ErrInvalid
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(envelope.Payload)
	provided, err := hex.DecodeString(envelope.MAC)
	if err != nil || !hmac.Equal(mac.Sum(nil), provided) {
		return ErrInvalid
	}
	var snapshot Snapshot
	if err := decodePolicyJSON(envelope.Payload, &snapshot); err != nil {
		return ErrInvalid
	}
	if err := snapshot.Validate(); err != nil {
		return err
	}
	digest := snapshot.Digest
	if err := sealSnapshot(&snapshot); err != nil {
		return err
	}
	if snapshot.Digest != digest {
		return ErrInvalid
	}
	s.key = key
	return s.publishLoaded(snapshot)
}

func (s *Store) publishLoaded(snapshot Snapshot) error {
	published, err := preparePublishedPolicy(snapshot)
	if err != nil {
		return err
	}
	key := new([32]byte)
	copy(key[:], s.key)
	s.identityKey.Store(key)
	s.current.Store(published)
	return nil
}

func decodePolicyJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func readPolicyFile(path string, limit int64) (data []byte, err error) {
	info, err := os.Lstat(path)
	if err != nil || !privatePolicyInfo(info, false) || info.Size() > limit {
		return nil, ErrUnavailable
	}
	file, err := openPolicyHandle(path, os.O_RDONLY)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			data, err = nil, ErrUnavailable
		}
	}()
	if err := checkPolicyHandle(file, path); err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnavailable
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("grouping: policy input exceeds size limit")
	}
	return data, err
}
