package middleware

type contextKey int

const (
	UserInfoContextKey contextKey = iota
	TokenContextKey
)

const (
	DaplaGroupAnnotation = "dapla.ssb.no/impersonate-group"
	UserNamespacePrefix  = "user-ssb-"
)
