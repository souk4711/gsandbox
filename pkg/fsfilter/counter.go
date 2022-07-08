package fsfilter

type Counter struct {
	v int
}

func (c *Counter) Inc() int {
	c.v++
	return c.v
}
