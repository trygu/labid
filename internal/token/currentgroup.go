package token

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwt"
	corev1 "k8s.io/api/core/v1"
)

type ServiceAccountGetter func(ctx context.Context, name, namespace string) (*corev1.ServiceAccount, error)

func CurrentGroupMapper(ctx context.Context, getSa ServiceAccountGetter) func(ctx context.Context, name, namespace string) Mapper {
	return func(_ context.Context, name, namespace string) Mapper {
		return func(ctx context.Context, builder *jwt.Builder) error {
			sa, err := getSa(ctx, name, namespace)
			if err != nil {
				return err
			}
			if group, ok := sa.Annotations[DaplaGroupAnnotation]; ok {
				builder.Claim("dapla.group", group)
				return nil
			}
			return errors.New("service account has no associated group")
		}
	}
}
