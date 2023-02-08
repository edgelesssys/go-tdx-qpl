package types

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalTCBInfo(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	infoJSON, err := os.ReadFile("../../blobs/tcb_info.json")
	require.NoError(err)

	var jsonBlob struct {
		TCBInfo TCBInfo `json:"tcbInfo"`
	}
	err = json.Unmarshal(infoJSON, &jsonBlob)
	assert.NoError(err)
}

func TestUnmarshalQEIdentity(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	infoJSON, err := os.ReadFile("../../blobs/qe_identity.json")
	require.NoError(err)

	var jsonBlob struct {
		QEIdentity QEIdentity `json:"enclaveIdentity"`
	}
	err = json.Unmarshal(infoJSON, &jsonBlob)
	assert.NoError(err)
}
