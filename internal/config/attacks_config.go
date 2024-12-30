package config

// AttackConfig defines the attack types to perform
type AttackConfig struct {
	HP, LP, NP      bool
	RPP, BPP        bool
	MR, RPW, BPW    bool
	RPS, RPSPP      bool
	JSON, ALL, FUZZ bool
}

// SharedAttackConfig holds the default configuration for attacks
var SharedAttackConfig = AttackConfig{
	HP:    false,
	LP:    false,
	NP:    false,
	RPP:   false,
	BPP:   false,
	MR:    false,
	RPW:   false,
	BPW:   false,
	RPS:   false,
	RPSPP: false,
	JSON:  false,
	FUZZ:  false,
	ALL:   false,
}
