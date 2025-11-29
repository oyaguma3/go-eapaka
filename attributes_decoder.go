package eapaka

import (
	"fmt"
)

// decodeAttribute creates a specific Attribute struct based on the type and unmarshals the data.
func decodeAttribute(t AttributeType, data []byte) (Attribute, error) {
	var attr Attribute

	switch t {
	case AT_RAND:
		attr = &AtRand{}
	case AT_AUTN:
		attr = &AtAutn{}
	case AT_RES:
		attr = &AtRes{}
	case AT_AUTS:
		attr = &AtAuts{}
	case AT_MAC:
		attr = &AtMac{}
	case AT_IDENTITY:
		attr = &AtIdentity{}
	case AT_PERMANENT_ID_REQ:
		attr = &AtPermanentIdReq{}
	case AT_ANY_ID_REQ:
		attr = &AtAnyIdReq{}
	case AT_FULLAUTH_ID_REQ:
		attr = &AtFullauthIdReq{}
	case AT_RESULT_IND:
		attr = &AtResultInd{}
	case AT_BIDDING:
		attr = &AtBidding{}
	case AT_CHECKCODE:
		attr = &AtCheckcode{}
	case AT_PADDING:
		attr = &AtPadding{}
	case AT_KDF_INPUT:
		attr = &AtKdfInput{}
	case AT_KDF:
		attr = &AtKdf{}
	case AT_NONCE_MT:
		attr = &AtNonceMt{}
	case AT_NOTIFICATION:
		attr = &AtNotification{}
	case AT_VERSION_LIST:
		attr = &AtVersionList{}
	case AT_SELECTED_VERSION:
		attr = &AtSelectedVersion{}
	case AT_COUNTER:
		attr = &AtCounter{}
	case AT_COUNTER_TOO_SMALL:
		attr = &AtCounterTooSmall{}
	case AT_NONCE_S:
		attr = &AtNonceS{}
	case AT_CLIENT_ERROR_CODE:
		attr = &AtClientErrorCode{}
	case AT_IV:
		attr = &AtIv{}
	case AT_ENCR_DATA:
		attr = &AtEncrData{}
	case AT_NEXT_PSEUDONYM:
		attr = &AtNextPseudonym{}
	case AT_NEXT_REAUTH_ID:
		attr = &AtNextReauthId{}
	default:
		// Unknown attributes are handled as GenericAttribute
		attr = &GenericAttribute{AttrType: t}
	}

	if err := attr.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attribute type %d: %w", t, err)
	}

	return attr, nil
}
