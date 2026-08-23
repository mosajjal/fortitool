package rootfscrypto

// fortRC4 is Fortinet's "FORT-RC4" stream cipher (FortiOS 8.0, PKCS#1-signed
// 32-byte key). Standard RC4 KSA, then a modified PRGA that mixes two
// cross-rotated S-box lookups with a 0xAA constant. Two silicon-level
// variants exist depending on whether the compiled kernel zeroes i/j before
// the PRGA loop (FGT) or lets KSA's final j flow through (FFW).
func fortRC4(key, data []byte, resetJ bool) []byte {
	var s [256]byte
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	klen := len(key)
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%klen])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}

	i := 0
	if resetJ {
		j = 0
	}

	out := make([]byte, len(data))
	for k := range data {
		i = (i + 1) & 0xFF
		si := s[i]
		j = (j + int(si)) & 0xFF
		sj := s[j]
		s[i], s[j] = sj, si

		t1 := (int(si) + int(sj)) & 0xFF
		idx1 := ((i << 5) ^ (j >> 3)) & 0xFF
		idx2 := ((j << 5) ^ (i >> 3)) & 0xFF
		mixIdx := ((int(s[idx2]) + int(s[idx1])) ^ 0xAA) & 0xFF
		b := (int(s[t1]) + int(s[mixIdx])) & 0xFF
		u := (int(sj) + j) & 0xFF

		out[k] = data[k] ^ byte(b^int(s[u]))
	}
	return out
}

// modifiedRC4 is FortiOS 7.6.x's distinct modified-RC4 rootfs cipher:
// standard KSA, then a PRGA with cross-rotated i/j byte halves and a
// multi-lookup output mix using the constant 0xFFFFFFAA. keepJ selects
// whether PRGA continues from KSA's final j (some kernel builds) or resets
// it to 0 (others) -- callers should try both and pick whichever output
// starts with the gzip magic.
func modifiedRC4(key, data []byte, keepJ bool) []byte {
	var s [256]byte
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i&0x1F])) & 0xFF
		s[i], s[j] = s[j], s[i]
	}

	const w14 uint32 = 0xFFFFFFAA
	i := 0
	if !keepJ {
		j = 0
	}

	out := make([]byte, len(data))
	for pos := range data {
		ct := data[pos]
		i = (i + 1) & 0xFF

		iLo := (i & 0x1F) << 3
		iHi := (i >> 5) & 0x7

		si := s[i]
		j = (j + int(si)) & 0xFF

		jLo := (j & 0x1F) << 3
		jHi := (j >> 5) & 0x7

		iRot := (iLo | jHi) & 0xFF
		jRot := (jLo | iHi) & 0xFF

		sj := s[j]
		s[i] = sj
		s[j] = si

		t := (int(si) + int(sj)) & 0xFF
		u := (int(sj) + j) & 0xFF

		v1 := int(((uint32(s[iRot]) + uint32(s[jRot])) ^ w14) & 0xFF)
		v2 := ((int(s[v1]) + int(s[t])) ^ int(s[u]) ^ int(ct)) & 0xFF
		out[pos] = byte(v2)
	}
	return out
}
