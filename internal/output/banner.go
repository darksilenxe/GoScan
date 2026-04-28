package output

import (
	"fmt"
	"io"
	"math/rand/v2"
)

var startupGophers = []string{
	"\n" +
		"   ,_---~~~~~----._\n" +
		"_,,_,*^____      _____``*g*\\\"*,\n" +
		"/ __/ /'     ^.  /      \\ ^@q   f\n" +
		"[  @f | @))    |  | @))   l  0 _/\n" +
		" \\`/   \\~____ / __ \\_____/    \\\n" +
		"  |           _l__l_           I\n" +
		"  }          [______]          I\n" +
		"  ]            | | |           |\n" +
		"  ]             ~ ~            |\n" +
		"  |      (^_^) /               |\n" +
		"   |   GoScan is starting!    |\n",
	"\n" +
		"   ,_---~~~~~----._\n" +
		"_,,_,*^____      _____``*g*\\\"*,\n" +
		"/ __/ /'     ^.  /      \\ ^@q   f\n" +
		"[  @f | @))    |  | @))   l  0 _/\n" +
		" \\`/   \\~____ / __ \\_____/    \\\n" +
		"  |           _l__l_           I\n" +
		"  }          [______]          I\n" +
		"  ]            | | |           |\n" +
		"  ]             ~ ~            |\n" +
		"  |               \\ (^_^)      |\n" +
		"   |   GoScan is starting!    |\n",
	"\n" +
		"   ,_---~~~~~----._\n" +
		"_,,_,*^____      _____``*g*\\\"*,\n" +
		"/ __/ /'     ^.  /      \\ ^@q   f\n" +
		"[  @f | @))    |  | @))   l  0 _/\n" +
		" \\`/   \\~____ / __ \\_____/    \\\n" +
		"  |           _l__l_           I\n" +
		"  }          [______]          I\n" +
		"  ]            | | |           |\n" +
		"  ]             ~ ~            |\n" +
		"  |          \\o(^_^)o/         |\n" +
		"   |   GoScan is starting!    |\n",
}

func startupBannerAt(index int) string {
	return startupGophers[index%len(startupGophers)]
}

// WriteStartupBanner writes the Go Gopher startup banner.
func WriteStartupBanner(w io.Writer) {
	fmt.Fprint(w, startupBannerAt(rand.IntN(len(startupGophers))))
}
