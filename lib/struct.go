package client

import (
    "github.com/hunkeelin/pki"
)
type WriteInfo struct {
    Path string
    CA string
    CAport string
    Chain bool
    CSRConfig *klinpki.CSRConfig // import github.com/hunkeelin/pki and read the godocs
}
