package apiserver

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Directory is the ext.Directory of this apiserver: IAM operations an
// extension makes as its configured actor (SSO provisioning, spec §39).
func (s *Server) Directory() ext.Directory { return directory{s.iam} }

type directory struct{ iam pb.IAMClient }

func (d directory) CreatePrincipal(ctx context.Context, actor, project, id, kind string) error {
	r, err := d.iam.CreatePrincipal(ctx, &pb.CreatePrincipalRequest{Actor: actor, Project: project, Id: id, Kind: kind})
	if err != nil {
		if rpcutil.Reason(err) == rpcutil.Invalid && strings.HasSuffix(rpcutil.Message(err), "exists") {
			return ext.ErrExists
		}
		return err
	}
	// The principal authenticates through its extension only: the token
	// IAM made with it is revoked at once.
	_, err = d.iam.RevokeToken(ctx, &pb.RevokeTokenRequest{Actor: actor, Principal: id, TokenId: r.GetTokenInfo().GetId()})
	return err
}

func (d directory) SetGrants(ctx context.Context, actor, project, principal string, perms []string) error {
	p, err := d.iam.GetProject(ctx, &pb.GetProjectRequest{Actor: actor, Project: project})
	if err != nil {
		return err
	}
	have := p.GetPolicies()[principal].GetPerms()
	var add, drop []string
	for _, x := range perms {
		if !slices.Contains(have, x) {
			add = append(add, x)
		}
	}
	for _, x := range have {
		if !slices.Contains(perms, x) {
			drop = append(drop, x)
		}
	}
	if len(add) > 0 {
		if _, err := d.iam.Grant(ctx, &pb.GrantRequest{Actor: actor, Project: project, Principal: principal, Perms: add}); err != nil {
			return err
		}
	}
	if len(drop) > 0 {
		if _, err := d.iam.Revoke(ctx, &pb.RevokeRequest{Actor: actor, Project: project, Principal: principal, Perms: drop}); err != nil {
			return err
		}
	}
	return nil
}

// The extensions' state lives under ext/ in IAM's key-value area; IAM
// lets apiservers reach nothing else there.
const statePrefix = "ext/"

func (d directory) GetState(ctx context.Context, key string) ([]byte, uint64, error) {
	e, err := d.iam.KVGet(ctx, &pb.KVGetRequest{Key: statePrefix + key})
	if err != nil {
		return nil, 0, err
	}
	return e.GetValue(), e.GetRev(), nil
}

func (d directory) PutState(ctx context.Context, key string, value []byte, rev uint64) error {
	_, err := d.iam.KVPut(ctx, &pb.KVPutRequest{Key: statePrefix + key, Value: value, Check: true, ExpectRev: rev})
	if rpcutil.ReasonOf(err) == rpcutil.Conflict {
		return errors.Join(ext.ErrConflict, err)
	}
	return err
}
