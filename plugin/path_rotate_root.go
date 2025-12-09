package minio

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v3"
)

// pathConfigRotateRoot defines the endpoint for rotating the MinIO service
// account credentials currently in use by the backend.
func (b *minioBackend) pathConfigRotateRoot() *framework.Path {

	return &framework.Path{
		Pattern: "config/rotate-root",

		HelpSynopsis: `
Rotate the secret key for the MinIO service account used by this secrets engine.
`,

		HelpDescription: `
This endpoint forces a rotation of the secret key associated with the MinIO
service account used by the Vault MinIO secrets engine. A new service account
secret key is generated through the MinIO Admin API and replaces the stored
credentials in this engine's configuration.

Credential rotation improves security by reducing the lifetime of existing
credentials and ensures that Vault is the only entity with knowledge of the
new secret key.

Rotation can only be performed when the engine is configured to use a service
account. If the engine is still configured with a root account, this operation
will return an error. Use the "config/service-account" endpoint first to
convert the configuration to a service account.

Example:
  vault write <mount>/config/rotate-root

No parameters are required for this operation. Vault generates the new secret
key automatically and updates the engine configuration.
`,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRoot,
			},
		},
	}
}

// pathRotateRoot rotates the secret key of the configured MinIO service
// account and updates the stored configuration.
func (b *minioBackend) pathRotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	c, err := b.GetConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if !c.IsServiceAccount {
		return nil, logical.CodedError(400, "Cannot rotate root credentials if this is not a service account, upgrade to service account")
	}

	secretAccessKey, err := b.generateSecretAccessKey()
	if err != nil {
		return nil, err
	}

	err = b.client.UpdateServiceAccount(ctx, NAME, madmin.UpdateServiceAccountReq{
		NewSecretKey: secretAccessKey,
	})
	if err != nil {
		return nil, err
	}

	data := &framework.FieldData{
		Schema: configSchema,
		Raw: map[string]interface{}{
			"secretAccessKey": secretAccessKey,
		},
	}
	return b.pathConfigUpdate(ctx, req, data)
}
