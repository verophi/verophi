// Package maven implements Maven version comparison following the Maven
// ComparableVersion algorithm. Vendored from github.com/masahiro331/go-mvn-version
// (commit d21fcd2e7de1, Apache-2.0) with the MNG-6420 test case enabled.
package maven

import (
	"fmt"
	"strconv"
	"strings"
)

var (
	qualifiers          = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}
	aliases             = map[string]string{"ga": "", "final": "", "release": "", "cr": "rc"}
	releaseVersionIndex = fmt.Sprint(indexOf("", qualifiers))
)

// Version is a parsed Maven version.
type Version struct {
	Value string
	items listItem
}

// NewVersion parses a Maven version string.
func NewVersion(v string) (Version, error) {
	return Version{
		Value: v,
		items: parseVersion(v),
	}, nil
}

func (v1 Version) String() string { return v1.Value }

// Compare returns -1, 0, or 1.
func (v1 Version) Compare(v2 Version) int { return v1.items.compare(v2.items) }

// item is a parsed segment (int, string, or sub-list).
type item interface {
	compare(v2 item) int
	isNull() bool
}

func parseItem(isDigit bool, s string) item {
	if isDigit {
		i, _ := strconv.Atoi(s)
		return intItem(i)
	}
	return newStringItem(s, false)
}

type intItem int

func (a intItem) compare(b item) int {
	if b == nil {
		if a == 0 {
			return 0
		}
		return 1
	}
	switch t := b.(type) {
	case intItem:
		return compareInt(int(a), int(t))
	case stringItem:
		return 1
	case listItem:
		return 1
	}
	return 0
}

func (a intItem) isNull() bool { return a == 0 }

type stringItem string

func newStringItem(value string, followedByDigit bool) stringItem {
	if followedByDigit {
		switch value {
		case "a":
			return "alpha"
		case "b":
			return "beta"
		case "m":
			return "milestone"
		}
	}
	if v, ok := aliases[value]; ok {
		return stringItem(v)
	}
	return stringItem(value)
}

func (a stringItem) compare(b item) int {
	if b == nil {
		return strings.Compare(a.comparableQualifier(), releaseVersionIndex)
	}
	switch v := b.(type) {
	case intItem:
		return -1
	case stringItem:
		return strings.Compare(a.comparableQualifier(), v.comparableQualifier())
	case listItem:
		return -1
	}
	return 0
}

func (a stringItem) isNull() bool { return a == "" }

func (a stringItem) comparableQualifier() string {
	index := indexOf(string(a), qualifiers)
	if index == -1 {
		return fmt.Sprintf("%d-%s", len(qualifiers), a)
	}
	return fmt.Sprint(index)
}

func indexOf(s string, sa []string) int {
	for i, q := range sa {
		if q == s {
			return i
		}
	}
	return -1
}

type listItem []item

func (a listItem) compare(b item) int {
	if b == nil {
		if len(a) == 0 {
			return 0
		}
		for _, it := range a {
			if result := it.compare(nil); result != 0 {
				return result
			}
		}
		return 0
	}
	switch v := b.(type) {
	case intItem:
		return -1
	case stringItem:
		return 1
	case listItem:
		iter := zip(a, v)
		for tuple := iter(); tuple != nil; tuple = iter() {
			l, r := tuple[0], tuple[1]
			var result int
			if l == nil {
				result = -1 * r.compare(l)
			} else {
				result = l.compare(r)
			}
			if result != 0 {
				return result
			}
		}
		return 0
	}
	return 0
}

func (a listItem) isNull() bool { return len(a) == 0 }

func (a listItem) normalize() listItem {
	ret := a
	for i := len(a) - 1; i >= 0; i-- {
		if a[i].isNull() {
			ret = ret[:i]
		} else if _, ok := a[i].(listItem); !ok {
			break
		}
	}
	return ret
}

func zip(a, b listItem) func() []item {
	i := 0
	return func() []item {
		var x, y item
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x == nil && y == nil {
			return nil
		}
		i++
		return []item{x, y}
	}
}

func parseVersion(v string) listItem {
	stack := &listItemStack{}
	var list listItem

	isDigit := false
	startIndex := 0
	str := strings.ToLower(v)
	sa := strings.Split(str, "")
	for i, c := range sa {
		if c == "." {
			if i == startIndex {
				list = append(list, intItem(0))
			} else {
				list = append(list, parseItem(isDigit, str[startIndex:i]))
			}
			startIndex = i + 1
		} else if c == "-" {
			if i == startIndex {
				list = append(list, intItem(0))
			} else {
				list = append(list, parseItem(isDigit, str[startIndex:i]))
			}
			startIndex = i + 1
			stack.push(list)
			list = listItem{}
		} else if _, err := strconv.Atoi(c); err == nil {
			if !isDigit && i > startIndex {
				list = append(list, newStringItem(str[startIndex:i], true))
				startIndex = i
				stack.push(list)
				list = listItem{}
			}
			isDigit = true
		} else {
			if isDigit && i > startIndex {
				list = append(list, parseItem(true, str[startIndex:i]))
				startIndex = i
				stack.push(list)
				list = listItem{}
			}
			isDigit = false
		}
	}
	if len(v) > startIndex {
		list = append(list, parseItem(isDigit, str[startIndex:]))
		stack.push(list)
	}
	if stack.isEmpty() {
		stack.push(list)
	}

	ret := stack.pop().normalize()
	for !stack.isEmpty() {
		ret = append(stack.pop().normalize(), ret)
	}
	return ret
}

func compareInt(a, b int) int {
	if a == b {
		return 0
	} else if a > b {
		return 1
	}
	return -1
}
