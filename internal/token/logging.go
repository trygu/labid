package token

import (
	"log/slog"

	"github.com/ogen-go/ogen/middleware"
)

func Logging(log *slog.Logger) middleware.Middleware {
	return func(req middleware.Request, next middleware.Next) (middleware.Response, error) {
		log := log.With(
			slog.String("operation", req.OperationName),
			slog.String("operationId", req.OperationID),
			slog.String("userAgent", req.Raw.UserAgent()),
			slog.String("remoteAddress", req.Raw.RemoteAddr),
		)

		log.Info("handle request")
		res, err := next(req)
		if err != nil {
			log.Error(err.Error())
		}

		return res, err
	}
}
