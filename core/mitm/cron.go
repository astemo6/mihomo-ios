package mitm

// Minimal cron expression parser for cron scripts (Surge cronexp, Loon cron "…", QX task_local,
// Stash cron.script). 5 fields (min hour dom mon dow) or 6 fields with leading seconds (QX).
// Supports *, ?, lists, ranges, steps and month / weekday names; dow 0 and 7 = Sunday.
// When both dom and dow are restricted the job runs when either matches (Vixie cron).

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Cron struct {
	expr             string
	sec, min, hour   uint64
	dom, mon, dow    uint64
	domStar, dowStar bool
	hasSeconds       bool
}

var monNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
var dowNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

var cronMacros = map[string]string{"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
	"@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}

func parseField(f string, lo, hi int, names map[string]int) (uint64, bool, error) {
	if f == "*" || f == "?" {
		var m uint64
		for i := lo; i <= hi; i++ {
			m |= 1 << uint(i)
		}
		return m, true, nil
	}
	var m uint64
	for _, part := range strings.Split(f, ",") {
		step := 1
		if i := strings.IndexByte(part, '/'); i >= 0 {
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s <= 0 {
				return 0, false, fmt.Errorf("步长无效：%s", part)
			}
			step, part = s, part[:i]
		}
		a, b := lo, hi
		if part != "*" && part != "?" {
			ra, rb, isRange := strings.Cut(part, "-")
			var err error
			if a, err = cronValue(ra, names); err != nil {
				return 0, false, err
			}
			b = a
			if isRange {
				if b, err = cronValue(rb, names); err != nil {
					return 0, false, err
				}
			} else if step > 1 {
				b = hi
			}
		}
		if names != nil && hi == 6 { // dow: 7 = Sunday
			if a == 7 && b == 7 {
				a, b = 0, 0
			} else if b == 7 {
				b = 6
				m |= 1
			}
		}
		if a < lo || b > hi || a > b {
			return 0, false, fmt.Errorf("超出范围：%s", part)
		}
		for i := a; i <= b; i += step {
			m |= 1 << uint(i)
		}
	}
	return m, false, nil
}

func cronValue(s string, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("无效的值：%s", s)
	}
	return v, nil
}

// ParseCron parses a cron expression.
func ParseCron(expr string) (*Cron, error) {
	e := strings.TrimSpace(strings.Trim(strings.TrimSpace(expr), `"'`))
	if m, ok := cronMacros[strings.ToLower(e)]; ok {
		e = m
	}
	f := strings.Fields(e)
	c := &Cron{expr: strings.Join(f, " ")}
	switch len(f) {
	case 5:
		f = append([]string{"0"}, f...)
	case 6:
		c.hasSeconds = true
	default:
		return nil, fmt.Errorf("cron 表达式需要 5 或 6 段：%s", expr)
	}
	var err error
	if c.sec, _, err = parseField(f[0], 0, 59, nil); err != nil {
		return nil, err
	}
	if c.min, _, err = parseField(f[1], 0, 59, nil); err != nil {
		return nil, err
	}
	if c.hour, _, err = parseField(f[2], 0, 23, nil); err != nil {
		return nil, err
	}
	if c.dom, c.domStar, err = parseField(f[3], 1, 31, nil); err != nil {
		return nil, err
	}
	if c.mon, _, err = parseField(f[4], 1, 12, monNames); err != nil {
		return nil, err
	}
	if c.dow, c.dowStar, err = parseField(f[5], 0, 6, dowNames); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cron) String() string { return c.expr }

func (c *Cron) dayOK(t time.Time) bool {
	d := c.dom&(1<<uint(t.Day())) != 0
	w := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.domStar && c.dowStar:
		return true
	case c.domStar:
		return w
	case c.dowStar:
		return d
	}
	return d || w
}

// Next returns the first fire time strictly after t (zero time if none within 5 years).
func (c *Cron) Next(t time.Time) time.Time {
	t = t.Truncate(time.Second).Add(time.Second)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if c.mon&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !c.dayOK(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}
		if c.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}
		if c.min&(1<<uint(t.Minute())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute()+1, 0, 0, t.Location())
			continue
		}
		if c.sec&(1<<uint(t.Second())) == 0 {
			t = t.Add(time.Second)
			continue
		}
		return t
	}
	return time.Time{}
}
