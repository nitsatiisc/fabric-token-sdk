/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testutils

import (
	"context"

	math "github.com/IBM/mathlib"
	v1 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/benchmark"
	math2 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/math"
	zkatdlog "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/driver"
	v1setup "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/setup"
	tokn "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/token"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/transfer"
	"github.com/LFDT-Panurus/panurus/token/driver"
	"github.com/LFDT-Panurus/panurus/token/driver/protos-go/v1/request"
	benchmark2 "github.com/LFDT-Panurus/panurus/token/services/benchmark"
	"github.com/LFDT-Panurus/panurus/token/services/logging"
	token2 "github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"go.opentelemetry.io/otel/trace/noop"
)

// NaiveTransfer is one transfer produced by the production stack, together with
// the openings its prover holds.
type NaiveTransfer struct {
	// Action is the transfer action, carrying the type-and-sum and range proofs.
	Action *transfer.Action
	// Request is the token request holding the action and the owner signatures. It
	// carries no auditor signature.
	Request *driver.TokenRequest
	// Signatures are the input owners' signatures over the request.
	Signatures [][]byte
	// Inputs and Outputs are the openings of the input and output commitments.
	Inputs  []*tokn.Metadata
	Outputs []*tokn.Metadata
}

// ProofSize returns the bytes a naive transfer spends on proving: the action's ZK
// proof and the owner signatures (each an Idemix proof of knowledge of a credential
// plus a pseudonym signature). The commitments and owners are public data that an
// aggregated transfer publishes as well, so they are not counted.
func (n *NaiveTransfer) ProofSize() int {
	size := len(n.Action.Proof)
	for _, s := range n.Signatures {
		size += len(s)
	}

	return size
}

// TransferProver produces naive transfers of a fixed shape with the production
// TransferService, so that a benchmark can time the prover alone: the services, the
// input tokens and the owner are set up once by NewTransferProver, and Prove runs
// only what a sender runs per transfer.
type TransferProver struct {
	// PP are the public parameters the transfers are made under.
	PP *v1setup.PublicParams
	// Owner is the identity owning every input and output.
	Owner *benchmark.OwnerIdentity

	service      *v1.TransferService
	wallet       *testOwnerWallet
	sender       *transfer.Sender
	ids          []*token2.ID
	outputTokens []*token2.Token
}

// NewTransferProver sets up naive transfers of benchCase's shape: NumInputs inputs,
// owned by the configuration's owner identity, and NumOutputs outputs to the same
// owner, with the input values and output split of the validator fixtures.
func NewTransferProver(benchCase *benchmark2.Case, configurations *benchmark.SetupConfigurations) (*TransferProver, error) {
	cfg, err := configurations.GetSetupConfiguration(benchCase.Bits, benchCase.CurveID)
	if err != nil {
		return nil, err
	}
	if benchCase.NumInputs <= 0 || benchCase.NumOutputs <= 0 {
		return nil, errors.Errorf("invalid transfer shape %d x %d", benchCase.NumInputs, benchCase.NumOutputs)
	}
	pp := cfg.PP
	oID := cfg.OwnerIdentity
	c := math.Curves[pp.Curve]

	inValues := make([]*math.Zr, benchCase.NumInputs)
	sum := uint64(0)
	for i := range inValues {
		v := uint64(i*10 + 500)
		sum += v
		inValues[i] = math2.NewCachedZrFromInt(c, v)
	}
	outValues := make([]uint64, benchCase.NumOutputs)
	for i := range outValues {
		outValues[i] = sum / uint64(benchCase.NumOutputs)
	}
	outValues[0] += sum - outValues[0]*uint64(benchCase.NumOutputs)

	rand, err := c.Rand()
	if err != nil {
		return nil, err
	}
	inBF := make([]*math.Zr, benchCase.NumInputs)
	for i := range inBF {
		inBF[i] = c.NewRandomZr(rand)
	}
	commitments := prepareTokens(inValues, inBF, "ABC", pp.PedersenGenerators, c)

	ids := make([]*token2.ID, benchCase.NumInputs)
	tokens := make([]*tokn.Token, benchCase.NumInputs)
	inputInf := make([]*tokn.Metadata, benchCase.NumInputs)
	signers := make([]driver.Signer, benchCase.NumInputs)
	for i := range ids {
		ids[i] = &token2.ID{TxId: "0", Index: uint64(i)}
		tokens[i] = &tokn.Token{Data: commitments[i], Owner: oID.ID}
		inputInf[i] = &tokn.Metadata{Type: "ABC", Value: inValues[i], BlindingFactor: inBF[i]}
		signers[i] = oID.Signer
	}

	ppm := &testPublicParamsManager{pp: pp}
	deserializer, err := zkatdlog.NewDeserializer(pp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create deserializer")
	}
	tokensService, err := tokn.NewTokensService(logging.MustGetLogger(), ppm, deserializer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tokens service")
	}
	loaded := make(map[string]v1.LoadedToken, len(tokens))
	for i, tok := range tokens {
		raw, err := tok.Serialize()
		if err != nil {
			return nil, err
		}
		meta, err := inputInf[i].Serialize()
		if err != nil {
			return nil, err
		}
		loaded[ids[i].String()] = v1.LoadedToken{Token: raw, Metadata: meta, TokenFormat: tokensService.OutputTokenFormat}
	}

	service := v1.NewTransferService(
		logging.MustGetLogger(),
		ppm,
		&testWalletService{auditInfoMap: map[string][]byte{string(oID.ID): oID.AuditInfo}},
		&testTokenLoader{tokens: loaded},
		deserializer,
		noop.NewTracerProvider(),
		tokensService,
	)
	sender, err := transfer.NewSender(signers, tokens, ids, inputInf, pp)
	if err != nil {
		return nil, err
	}

	outputTokens := make([]*token2.Token, benchCase.NumOutputs)
	for i := range outputTokens {
		outputTokens[i] = &token2.Token{Type: "ABC", Quantity: token2.NewQuantityFromUInt64(outValues[i]).Hex(), Owner: oID.ID}
	}

	return &TransferProver{
		PP:           pp,
		Owner:        oID,
		service:      service,
		wallet:       &testOwnerWallet{id: "test-owner-wallet", signer: oID.Signer},
		sender:       sender,
		ids:          ids,
		outputTokens: outputTokens,
	}, nil
}

// Prove produces one naive transfer: the transfer action with its ZK proof, and the
// input owners' signatures over the request anchored at anchor. This is the whole
// of the sender's cryptographic work; auditing and endorsement are not included.
func (p *TransferProver) Prove(ctx context.Context, anchor string) (*NaiveTransfer, error) {
	act, meta, err := p.service.Transfer(ctx, driver.TokenRequestAnchor(anchor), p.wallet, p.ids, p.outputTokens, &driver.TransferOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate the transfer")
	}
	action, ok := act.(*transfer.Action)
	if !ok {
		return nil, errors.Errorf("unexpected action type %T", act)
	}
	raw, err := action.Serialize()
	if err != nil {
		return nil, err
	}
	req := &driver.TokenRequest{Actions: []*driver.TypedAction{{Type: request.ActionType_ACTION_TYPE_TRANSFER, Raw: raw}}}
	msg, err := req.MarshalToMessageToSign([]byte(anchor))
	if err != nil {
		return nil, err
	}
	sigs, err := p.sender.SignTokenActions(msg)
	if err != nil {
		return nil, err
	}
	for _, s := range sigs {
		req.Signatures = append(req.Signatures, &driver.RequestSignature{Action: &driver.ActionSignature{ActionID: 0, Signature: s}})
	}

	out := &NaiveTransfer{Action: action, Request: req, Signatures: sigs, Inputs: p.sender.InputInformation}
	for j, o := range meta.Outputs {
		m := &tokn.Metadata{}
		if err := m.Deserialize(o.OutputMetadata); err != nil {
			return nil, errors.Wrapf(err, "failed to read the opening of output %d", j)
		}
		out.Outputs = append(out.Outputs, m)
	}

	return out, nil
}
