package configserver

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/concourse/atc"
	"github.com/concourse/atc/db"
	"github.com/mitchellh/mapstructure"
	"github.com/pivotal-golang/lager"
)

func (s *Server) SaveConfig(w http.ResponseWriter, r *http.Request) {
	session := s.logger.Session("set-config")

	configIDStr := r.Header.Get(atc.ConfigIDHeader)
	if len(configIDStr) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "no config ID specified")
		return
	}

	var id db.ConfigID
	_, err := fmt.Sscanf(configIDStr, "%d", &id)
	if err != nil {
		session.Error("malformed-config-id", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "config ID is malformed: %s", err)
		return
	}

	var configStructure interface{}
	err = json.NewDecoder(r.Body).Decode(&configStructure)
	if err != nil {
		session.Error("malformed-json", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var config atc.Config
	var md mapstructure.Metadata
	msConfig := &mapstructure.DecoderConfig{
		Metadata: &md,
		Result:   &config,
	}
	decoder, err := mapstructure.NewDecoder(msConfig)
	if err != nil {
		session.Error("failed-to-construct-decoder", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := decoder.Decode(configStructure); err != nil {
		session.Error("could-not-decode", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = mapstructure.Decode(configStructure, &config)
	if err != nil {
		session.Error("invalid-config-structure", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(md.Unused) != 0 {
		session.Error("extra-keys", err, lager.Data{
			"unused-keys": md.Unused,
		})
		w.WriteHeader(http.StatusBadRequest)

		fmt.Fprintln(w, "unknown/extra keys:")
		for _, unusedKey := range md.Unused {
			fmt.Fprintf(w, "  - %s\n", unusedKey)
		}
		return
	}

	err = s.validate(config)
	if err != nil {
		session.Error("ignoring-invalid-config", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "%s", err)
		return
	}

	session.Info("saving", lager.Data{"config": config})

	err = s.db.SaveConfig(config, id)
	if err != nil {
		session.Error("failed-to-save-config", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to save config: %s", err)
		return
	}

	session.Info("saved")

	w.WriteHeader(http.StatusOK)
}
