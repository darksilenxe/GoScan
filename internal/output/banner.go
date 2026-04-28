package output

import (
	"fmt"
	"io"
)

const startupGopher = "\n" +
	"   ,_---~~~~~----._\n" +
	"_,,_,*^____      _____``*g*\\\"*,\n" +
	"/ __/ /'     ^.  /      \\ ^@q   f\n" +
	"[  @f | @))    |  | @))   l  0 _/\n" +
	" \\`/   \\~____ / __ \\_____/    \\\n" +
	"  |           _l__l_           I\n" +
	"  }          [______]          I\n" +
	"  ]            | | |           |\n" +
	"  ]             ~ ~            |\n" +
	"  |                            |\n" +
	"   |   GoScan is starting!    |\n"

// WriteStartupBanner writes the Go Gopher startup banner.
func WriteStartupBanner(w io.Writer) {
	fmt.Fprint(w, startupGopher)
}
