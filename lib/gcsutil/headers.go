package gcsutil

import (
	"context"
	"fmt"
	"reflect"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// ignoreSigningHeaders excludes the listed headers
// from the request signature because some providers may alter them.
//
// See https://github.com/aws/aws-sdk-go-v2/issues/1816.
func IgnoreSigningHeaders(o *s3.Options, headers []string) {
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		if err := stack.Finalize.Insert(ignoreHeaders(headers), "Signing", middleware.Before); err != nil {
			return err
		}

		if err := stack.Finalize.Insert(restoreIgnored(), "Signing", middleware.After); err != nil {
			return err
		}

		return nil
	})
}

type ignoredHeadersKey struct{}

func ignoreHeaders(headers []string) middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"IgnoreHeaders",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(ignoreHeaders) unexpected request middleware type %T", in.Request)}
			}

			ignored := make(map[string]string, len(headers))
			for _, h := range headers {
				ignored[h] = req.Header.Get(h)
				req.Header.Del(h)
			}

			ctx = middleware.WithStackValue(ctx, ignoredHeadersKey{}, ignored)

			return next.HandleFinalize(ctx, in)
		},
	)
}

func restoreIgnored() middleware.FinalizeMiddleware {
	return middleware.FinalizeMiddlewareFunc(
		"RestoreIgnored",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (out middleware.FinalizeOutput, metadata middleware.Metadata, err error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return out, metadata, &v4.SigningError{Err: fmt.Errorf("(restoreIgnored) unexpected request middleware type %T", in.Request)}
			}

			ignored, _ := middleware.GetStackValue(ctx, ignoredHeadersKey{}).(map[string]string)
			for k, v := range ignored {
				req.Header.Set(k, v)
			}

			return next.HandleFinalize(ctx, in)
		},
	)
}

// disableTrailingChecksumForGCS disables trailing checksums for UploadPart and PutObject operations using reflection
// This is part of the GCS compatibility workaround as GCS doesn't support trailing checksums
func DisableTrailingChecksumForGCS(o *s3.Options) {
	o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc(
			"DisableTrailingChecksum",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (out middleware.InitializeOutput, metadata middleware.Metadata, err error) {
				// Check if this is an UploadPart or PutObject operation
				if opName := middleware.GetOperationName(ctx); opName == "UploadPart" || opName == "PutObject" {
					// Use reflection to disable trailing checksums in the checksum middleware
					// This is a hack, but it's the only way to disable trailing checksums currently
					if checksumMiddleware, ok := stack.Finalize.Get("AWSChecksum:ComputeInputPayloadChecksum"); ok {
						if v := reflect.ValueOf(checksumMiddleware).Elem(); v.IsValid() {
							if field := v.FieldByName("EnableTrailingChecksum"); field.IsValid() && field.CanSet() && field.Kind() == reflect.Bool {
								field.SetBool(false)
							}
						}
					}
					// Remove the trailing checksum middleware entirely
					_, _ = stack.Finalize.Remove("addInputChecksumTrailer")
				}
				return next.HandleInitialize(ctx, in)
			},
		), middleware.Before)
	})
}
