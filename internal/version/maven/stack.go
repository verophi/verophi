package maven

type listItemStack []listItem

func (s *listItemStack) isEmpty() bool { return len(*s) == 0 }

func (s *listItemStack) push(item listItem) { *s = append(*s, item) }

func (s *listItemStack) pop() listItem {
	if s.isEmpty() {
		return nil
	}
	ss := *s
	index := len(ss) - 1
	element := ss[index]
	*s = ss[:index]
	return element
}
