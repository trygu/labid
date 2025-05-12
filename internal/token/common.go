package token

const (
	DaplaGroupAnnotation = "dapla.ssb.no/impersonate-group"
	UserNamespacePrefix  = "user-ssb-"
)

type KubernetesMeta struct {
	Name      string
	Namespace string
}

type MapperContext struct {
	Username       string
	ServiceAccount KubernetesMeta
	Pod            KubernetesMeta
}
