package minio

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v3"
)

const NAME string = "vaultadmin:minio:service-account"

// pathServiceAccount defines the endpoint used to upgrade the backend
// configuration to use a MinIO service account instead of a root account.
func (b *minioBackend) pathServiceAccount() *framework.Path {

	return &framework.Path{
		Pattern: "config/service-account/",

		HelpSynopsis: `
Upgrade the MinIO configuration to use a dedicated service account instead of a root account.
`,

		HelpDescription: `
This endpoint converts the existing MinIO configuration from using a root user
to a dedicated MinIO service account intended exclusively for Vault. The
service account is created through the MinIO Admin API, and the newly generated
access key and secret key will replace the existing configuration.

Once the upgrade is complete, Vault will operate using the service account
credentials, improving security by avoiding use of a privileged account.

This operation can only be performed once. If a service account is already
configured, the request will return an error.

Example:
  vault write <mount>/config/service-account

No additional parameters are required. Vault automatically creates the service
account using the current MinIO access key and applies the credentials to the
engine configuration.
`,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathUpgradeToServiceAccount,
			},
		},
	}
}

// pathUpgradeToServiceAccount upgrades the backend configuration to use a
// dedicated MinIO service account rather than the configured root credentials.
func (b *minioBackend) pathUpgradeToServiceAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if c.IsServiceAccount {
		return nil, logical.CodedError(400, "The root Vault account is already a service account")
	}

	cred, err := b.client.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		TargetUser:  c.AccessKeyId,
		Name:        NAME,
		Policy:      nil,
		Description: "Service account used by Vault MinIO dynamic secrets engine",
	})
	if err != nil {
		return nil, err
	}

	return b.pathConfigUpdate(ctx, req, &framework.FieldData{
		Schema: configSchema,
		Raw: map[string]interface{}{
			"accessKeyId":     cred.AccessKey,
			"secretAccessKey": cred.SecretKey,
		},
	})
}
