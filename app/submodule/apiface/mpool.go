package apiface

import (
	"context"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/venus/pkg/messagepool"
	"github.com/filecoin-project/venus/pkg/types"
	"github.com/ipfs/go-cid"
)

type IMessagePool interface {
	// Rule[perm:read]
	DeleteByAdress(ctx context.Context, addr address.Address) error
	// Rule[perm:read]
	MpoolPublishByAddr(context.Context, address.Address) error
	// Rule[perm:read]
	MpoolPublishMessage(ctx context.Context, smsg *types.SignedMessage) error
	// Rule[perm:read]
	MpoolPush(ctx context.Context, smsg *types.SignedMessage) (cid.Cid, error)
	// Rule[perm:read]
	MpoolGetConfig(context.Context) (*messagepool.MpoolConfig, error)
	// Rule[perm:read]
	MpoolSetConfig(ctx context.Context, cfg *messagepool.MpoolConfig) error
	// Rule[perm:read]
	MpoolSelect(context.Context, types.TipSetKey, float64) ([]*types.SignedMessage, error)
	// Rule[perm:read]
	MpoolSelects(context.Context, types.TipSetKey, []float64) ([][]*types.SignedMessage, error)
	// Rule[perm:read]
	MpoolPending(ctx context.Context, tsk types.TipSetKey) ([]*types.SignedMessage, error)
	// Rule[perm:read]
	MpoolClear(ctx context.Context, local bool) error
	// Rule[perm:read]
	MpoolPushUntrusted(ctx context.Context, smsg *types.SignedMessage) (cid.Cid, error)
	// Rule[perm:read]
	MpoolPushMessage(ctx context.Context, msg *types.UnsignedMessage, spec *types.MessageSendSpec) (*types.SignedMessage, error)
	// Rule[perm:read]
	MpoolBatchPush(ctx context.Context, smsgs []*types.SignedMessage) ([]cid.Cid, error)
	// Rule[perm:read]
	MpoolBatchPushUntrusted(ctx context.Context, smsgs []*types.SignedMessage) ([]cid.Cid, error)
	// Rule[perm:read]
	MpoolBatchPushMessage(ctx context.Context, msgs []*types.UnsignedMessage, spec *types.MessageSendSpec) ([]*types.SignedMessage, error)
	// Rule[perm:read]
	MpoolGetNonce(ctx context.Context, addr address.Address) (uint64, error)
	// Rule[perm:read]
	MpoolSub(ctx context.Context) (<-chan messagepool.MpoolUpdate, error)
	// Rule[perm:read]
	SendMsg(ctx context.Context, from, to address.Address, method abi.MethodNum, value, maxFee abi.TokenAmount, params []byte) (cid.Cid, error)
	// Rule[perm:read]
	GasEstimateMessageGas(ctx context.Context, msg *types.UnsignedMessage, spec *types.MessageSendSpec, tsk types.TipSetKey) (*types.UnsignedMessage, error)
	// Rule[perm:read]
	GasEstimateFeeCap(ctx context.Context, msg *types.UnsignedMessage, maxqueueblks int64, tsk types.TipSetKey) (big.Int, error)
	// Rule[perm:read]
	GasEstimateGasPremium(ctx context.Context, nblocksincl uint64, sender address.Address, gaslimit int64, tsk types.TipSetKey) (big.Int, error)
	// Rule[perm:read]
	GasEstimateGasLimit(ctx context.Context, msgIn *types.UnsignedMessage, tsk types.TipSetKey) (int64, error)
}
