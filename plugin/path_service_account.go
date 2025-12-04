package minio

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/minio/madmin-go/v3"
)


const NAME string = "vaultadmin:minio:service-account"

func (b *minioBackend) pathServiceAccount() *framework.Path {

	return &framework.Path{
		Pattern:         "config/upgrade-service-account/",
		HelpSynopsis:    "",
		HelpDescription: "",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathUpgradeToServiceAccount,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRotateRoot,
			},
		},
	}
}

func (b *minioBackend) pathUpgradeToServiceAccount(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	c,err:= b.GetConfig(ctx,req.Storage)
	if err != nil{
		return nil, err
	}

	if c.IsServiceAccount {
		return nil, logical.CodedError(400,"The root vault account is already a service account")
	}
	
	cred, err:= b.client.AddServiceAccount(ctx, madmin.AddServiceAccountReq{
		TargetUser: c.AccessKeyId,
		Name: NAME,
		Policy: nil,
		Description: "Service account used by Vault MinIO dynamic secrets engine",
	})

	if err != nil {
		return nil,err
	}

	return b.pathConfigUpdate(ctx,req,&framework.FieldData{
		Schema: configSchema,
		Raw: map[string]interface{}{
			"accessKeyId": cred.AccessKey,
			"secretAccessKey": cred.SecretKey,
		},
	})
}

func (b *minioBackend) pathRotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	c,err:= b.GetConfig(ctx,req.Storage)
	if err!= nil {
		return nil,err
	}

	if !c.IsServiceAccount {
		return nil, logical.CodedError(400,"Cannot rotate root credentials if this is not a service account, upgrade to service account")
	}

	secretAccessKey, err := b.generateSecretAccessKey()

	if err != nil {
		return nil, err
	}

	err = b.client.UpdateServiceAccount(ctx,NAME,madmin.UpdateServiceAccountReq{
		NewSecretKey: secretAccessKey,
	})

	if err != nil{
		return nil,err
	}

	data := &framework.FieldData{
		Schema: configSchema,
		Raw: map[string]interface{}{
			"secretAccessKey": secretAccessKey,
		},
	}
	return b.pathConfigUpdate(ctx, req, data)
}
