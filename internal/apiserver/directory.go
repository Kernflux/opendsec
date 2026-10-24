package apiserver

import (
	"context"
	"slices"

	"github.com/kernflux/opendsec/ext"
	pb "github.com/kernflux/opendsec/gen/go/opendsec/v1"
	"github.com/kernflux/opendsec/internal/rpcutil"
)

// Directory is the ext.Directory of this apiserver: IAM operations an
// extension makes as its configured actor (SSO provisioning, spec §39).
func (s *Server) Directory() ext.Directory { return directory{s.iam} }

type directory struct{ iam pb.IAMClient }

func (d directory) EnsurePrincipal(ctx context.Context, actor, project, id, kind string) error {
	r, err := d.iam.CreatePrincipal(ctx, &pb.CreatePrincipalRequest{Actor: actor, Project: project, Id: id, Kind: kind})
	if err != nil {
		if rpcutil.Reason(err) == rpcutil.Invalid {
			// It exists (any other invalid request fails the grants next).
			if _, gerr := d.iam.ListTokens(ctx, &pb.ListTokensRequest{Actor: actor, Principal: id}); gerr == nil {
				return nil
			}
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
