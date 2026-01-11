package eapaka

import "errors"

// KdfValuesFromAttributes extracts AT_KDF values in order.
func KdfValuesFromAttributes(attrs []Attribute) []uint16 {
	var values []uint16
	for _, attr := range attrs {
		if kdfAttr, ok := attr.(*AtKdf); ok {
			values = append(values, kdfAttr.KDF)
		}
	}
	return values
}

// ValidateKdfOffer checks RFC 9048 Section 3.2 requirements for AT_KDF offers.
func ValidateKdfOffer(values []uint16) error {
	if len(values) == 0 {
		return errors.New("AT_KDF offer must include at least one value")
	}
	seen := make(map[uint16]struct{}, len(values))
	for _, v := range values {
		if v == KDFReserved {
			return errors.New("AT_KDF offer includes reserved value")
		}
		if _, ok := seen[v]; ok {
			return errors.New("AT_KDF offer includes duplicate values")
		}
		seen[v] = struct{}{}
	}
	return nil
}

// BuildKdfOfferAttributes builds a list of AT_KDF attributes from ordered values.
func BuildKdfOfferAttributes(values []uint16) ([]Attribute, error) {
	if err := ValidateKdfOffer(values); err != nil {
		return nil, err
	}
	return kdfAttributesFromValues(values), nil
}

// BuildKdfResponseAttributes builds a peer response with a single AT_KDF value.
func BuildKdfResponseAttributes(selected uint16) ([]Attribute, error) {
	if selected == KDFReserved {
		return nil, errors.New("AT_KDF selected value is reserved")
	}
	return []Attribute{&AtKdf{KDF: selected}}, nil
}

// ValidateKdfResponse validates a peer AT_KDF response against an offer.
// It returns the selected KDF value.
func ValidateKdfResponse(offer []uint16, response []uint16) (uint16, error) {
	if err := ValidateKdfOffer(offer); err != nil {
		return 0, err
	}
	if len(response) != 1 {
		return 0, errors.New("AT_KDF response must include exactly one value")
	}
	selected := response[0]
	if selected == offer[0] {
		return 0, errors.New("AT_KDF response repeats the preferred offer")
	}
	for _, v := range offer {
		if v == selected {
			return selected, nil
		}
	}
	return 0, errors.New("AT_KDF response value not offered")
}

// BuildKdfReofferAttributes builds a re-offer list after a peer selection.
// The selected value is added to the front and the full original list is retained.
func BuildKdfReofferAttributes(offer []uint16, selected uint16) ([]Attribute, error) {
	if err := ValidateKdfOffer(offer); err != nil {
		return nil, err
	}
	if selected == offer[0] {
		return nil, errors.New("AT_KDF selected value should not be the preferred offer")
	}
	found := false
	for _, v := range offer {
		if v == selected {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("AT_KDF selected value not offered")
	}
	values := make([]uint16, 0, len(offer)+1)
	values = append(values, selected)
	values = append(values, offer...)
	return kdfAttributesFromValues(values), nil
}

// ValidateKdfReoffer verifies that only the requested change occurred.
func ValidateKdfReoffer(offer []uint16, reoffer []uint16, selected uint16) error {
	if err := ValidateKdfOffer(offer); err != nil {
		return err
	}
	if len(reoffer) != len(offer)+1 {
		return errors.New("AT_KDF re-offer length mismatch")
	}
	if reoffer[0] != selected {
		return errors.New("AT_KDF re-offer does not start with selected value")
	}
	for i, v := range offer {
		if reoffer[i+1] != v {
			return errors.New("AT_KDF re-offer does not retain original ordering")
		}
	}
	return nil
}

func kdfAttributesFromValues(values []uint16) []Attribute {
	attrs := make([]Attribute, 0, len(values))
	for _, v := range values {
		attrs = append(attrs, &AtKdf{KDF: v})
	}
	return attrs
}
