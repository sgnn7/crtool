package version

import "fmt"

var Version = "0.0.3"
var Tag = "dev"

var FullVersionName = fmt.Sprintf("%s-%s", Version, Tag)
