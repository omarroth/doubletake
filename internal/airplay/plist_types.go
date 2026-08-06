package airplay

import (
	"encoding/hex"
	"fmt"
)

// data or hex string
type plistData []byte

func (d *plistData) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var data []byte
	if unmarshal(&data) == nil {
		*d = data
		return nil
	}
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("expected data or hex string: %w", err)
	}
	*d = b
	return nil
}

// integer or real
type plistNumber int

func (n *plistNumber) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var i int64
	if unmarshal(&i) == nil {
		*n = plistNumber(i)
		return nil
	}
	var f float64
	if err := unmarshal(&f); err != nil {
		return err
	}
	*n = plistNumber(f)
	return nil
}

// boolean or 0/1
type plistFlag bool

func (b *plistFlag) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var v bool
	if unmarshal(&v) == nil {
		*b = plistFlag(v)
		return nil
	}
	var i int64
	if err := unmarshal(&i); err != nil {
		return err
	}
	*b = i != 0
	return nil
}
