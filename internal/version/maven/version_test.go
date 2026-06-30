package maven

import "testing"

func TestEqual(t *testing.T) {
	cases := []struct{ v1, v2 string }{
		{"1--1", "1-0-1"},
		{"1..1", "1.0.1"},
		{"1-ga", "1"},
		{"1.0.0.RELEASE", "1"},
		{"1.0.0.FINAL", "1"},
		{"1.0.0.FINAL", "1.RELEASE"},
		{"1.2.3-a1b1-m1", "1.2.3-alpha-1-beta-1-milestone-1"},
		{"1.2.3-rc", "1.2.3-cr"},
		{"-1", "0-1"},
		{"1-1.0", "1-1"},
		{"1.", "1-"},
		{"1-1.ga", "1-1-ga"},
		{"1-1.ga", "1-1.0"},
	}
	for _, tc := range cases {
		a, _ := NewVersion(tc.v1)
		b, _ := NewVersion(tc.v2)
		if a.Compare(b) != 0 {
			t.Errorf("expected %s == %s", tc.v1, tc.v2)
		}
	}
}

func TestNotEqual(t *testing.T) {
	cases := []struct{ v1, v2 string }{
		{"1--1", "1-1"},
		{"1.1", "1.0.1"},
		{"1-sp", "1"},
		{"5.0.0.RELEASE", "4.9.9.RELEASE"},
		{"-1", "1"},
	}
	for _, tc := range cases {
		a, _ := NewVersion(tc.v1)
		b, _ := NewVersion(tc.v2)
		if a.Compare(b) == 0 {
			t.Errorf("expected %s != %s", tc.v1, tc.v2)
		}
	}
}

func TestGreaterThan(t *testing.T) {
	cases := []struct{ v1, v2 string }{
		{"1", "1.alpha"},
		{"1.1", "1.0"},
		{"1.a", "1.0"},
		{"1", "1-alpha"},
		{"1.1", "1.0.1"},
		{"1-sp", "1"},
		{"1.2.3", "1.2.3-a1"},
		{"1.2.3-b1", "1.2.3-a1"},
		{"1.2.3-m1", "1.2.3-b1"},
		{"1.2.3-rc", "1.2.3-m1"},
		{"1.2.3-a2", "1.2.3-a1"},
		{"1.2.3-b1", "1.2.3-a2"},
		{"1.2.3", "1.2.3-cr"},
		{"5.0.0.RELEASE", "4.9.9.RELEASE"},
		{"1", "-1"},
		{"1-0.3", "1"},
		{"1-foo", "1.foo"},
		{"1-1", "1-foo"},
		{"1.1", "1-1"},
		{"1-1-foo", "1-1.foo"},
		{"1.foo-1", "1"},
	}
	for _, tc := range cases {
		a, _ := NewVersion(tc.v1)
		b, _ := NewVersion(tc.v2)
		if a.Compare(b) <= 0 {
			t.Errorf("expected %s > %s", tc.v1, tc.v2)
		}
	}
}

func TestLessThan(t *testing.T) {
	cases := []struct{ v1, v2 string }{
		{"1.alpha", "1"},
		{"1.0", "1.1"},
		{"1.0", "1.a"},
		{"1-alpha", "1"},
		{"1--1", "1-1"},
		{"1.0.1", "1.0.11"},
		{"1.0.1", "1.1"},
		{"1-0", "1-sp"},
		{"1.2.3-a1", "1.2.3"},
		{"1.2.3-a1", "1.2.3-b1"},
		{"1.2.3-b1", "1.2.3-m1"},
		{"1.2.3-m1", "1.2.3-rc"},
		{"1.2.3-a1", "1.2.3-a2"},
		{"1.2.3-a2", "1.2.3-b1"},
		{"1.2.3-cr", "1.2.3"},
		{"4.9.9.RELEASE", "5.0.0.RELEASE"},
		{"0-1", "1"},
	}
	for _, tc := range cases {
		a, _ := NewVersion(tc.v1)
		b, _ := NewVersion(tc.v2)
		if a.Compare(b) >= 0 {
			t.Errorf("expected %s < %s", tc.v1, tc.v2)
		}
	}
}

func TestVersionQualifier(t *testing.T) {
	sorted := []string{
		"1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123",
		"1-m2", "1-m11", "1-rc", "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp",
		"1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1", "1-1-snapshot", "1-1",
		"1-2", "1-123",
	}
	for i := 1; i < len(sorted); i++ {
		low, _ := NewVersion(sorted[i-1])
		for j := i; j < len(sorted); j++ {
			high, _ := NewVersion(sorted[j])
			if low.Compare(high) >= 0 {
				t.Errorf("expected %s < %s", sorted[i-1], sorted[j])
			}
		}
	}
}

// TestVersionsNumber includes the MNG-6420 case (2.0.0.a) that was previously
// commented out. The current implementation handles it correctly.
func TestVersionsNumber(t *testing.T) {
	sorted := []string{
		"2.0", "2-1", "2.0.a",
		"2.0.0.a", // MNG-6420: must sort between 2.0.a and 2.0.2
		"2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1",
		"2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11",
		"11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
	}
	for i := 1; i < len(sorted); i++ {
		low, _ := NewVersion(sorted[i-1])
		for j := i; j < len(sorted); j++ {
			high, _ := NewVersion(sorted[j])
			if low.Compare(high) >= 0 {
				t.Errorf("expected %s < %s", sorted[i-1], sorted[j])
			}
		}
	}
}

// TestRealWorldMavenVersions exercises the version comparisons our SBOM fixture
// contains (log4j, jackson, spring).
func TestRealWorldMavenVersions(t *testing.T) {
	cases := []struct{ lower, higher string }{
		{"2.14.1", "2.15.0"},
		{"2.14.1", "2.17.1"},
		{"2.3.1", "2.14.1"},
		{"2.12.2", "2.14.1"},
		{"2.9.10", "2.15.0"},
		{"5.3.19", "5.3.20"},
		{"1.0.0", "1.0.1"},
	}
	for _, tc := range cases {
		a, _ := NewVersion(tc.lower)
		b, _ := NewVersion(tc.higher)
		if a.Compare(b) >= 0 {
			t.Errorf("expected %s < %s", tc.lower, tc.higher)
		}
	}
}
