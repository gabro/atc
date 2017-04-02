package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/concourse/atc"
)

func (db *SQLDB) GetTeams() ([]SavedTeam, error) {
	rows, err := db.conn.Query(`
		SELECT id, name, admin, basic_auth, github_auth, uaa_auth, genericoauth_auth FROM teams
	`)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	teams := []SavedTeam{}

	for rows.Next() {
		team, err := scanTeam(rows)

		if err != nil {
			return nil, err
		}

		teams = append(teams, team)
	}

	return teams, nil
}

func (db *SQLDB) CreateDefaultTeamIfNotExists() error {
	var id sql.NullInt64
	err := db.conn.QueryRow(`
			SELECT id
			FROM teams
			WHERE name = $1
		`, atc.DefaultTeamName).Scan(&id)

	if err != nil {
		if err == sql.ErrNoRows {
			err = db.conn.QueryRow(`
				INSERT INTO teams (
					name, admin
				)
				VALUES ($1, true)
				RETURNING id
			`, atc.DefaultTeamName).Scan(&id)
			if err != nil {
				return err
			}

			if !id.Valid {
				return errors.New("could-not-unmarshal-id")
			}
			createTableString := fmt.Sprintf(`
						CREATE TABLE team_build_events_%d ()
						INHERITS (build_events);`, id.Int64)
			_, err = db.conn.Exec(createTableString)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		_, err = db.conn.Exec(`
			UPDATE teams
			SET admin = true
			WHERE LOWER(name) = LOWER($1)
		`, atc.DefaultTeamName)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *SQLDB) CreateTeam(team Team) (SavedTeam, error) {
	return SavedTeam{}, errors.New("AH")
}

func scanTeam(rows scannable) (SavedTeam, error) {
	var basicAuth, gitHubAuth, uaaAuth, genericOAuth sql.NullString
	var savedTeam SavedTeam

	err := rows.Scan(
		&savedTeam.ID,
		&savedTeam.Name,
		&savedTeam.Admin,
		&basicAuth,
		&gitHubAuth,
		&uaaAuth,
		&genericOAuth,
	)
	if err != nil {
		return savedTeam, err
	}

	if basicAuth.Valid {
		err = json.Unmarshal([]byte(basicAuth.String), &savedTeam.BasicAuth)
		if err != nil {
			return savedTeam, err
		}
	}

	if gitHubAuth.Valid {
		err = json.Unmarshal([]byte(gitHubAuth.String), &savedTeam.GitHubAuth)
		if err != nil {
			return savedTeam, err
		}
	}

	if uaaAuth.Valid {
		err = json.Unmarshal([]byte(uaaAuth.String), &savedTeam.UAAAuth)
		if err != nil {
			return savedTeam, err
		}
	}

	if genericOAuth.Valid {
		err = json.Unmarshal([]byte(genericOAuth.String), &savedTeam.GenericOAuth)
		if err != nil {
			return savedTeam, err
		}
	}

	return savedTeam, nil
}

//func scanTeam(rows scannable) (SavedTeam, error) {
//	var basicAuth, auth sql.NullString
//	var savedTeam SavedTeam
//
//	err := rows.Scan(
//		&savedTeam.ID,
//		&savedTeam.Name,
//		&savedTeam.Admin,
//		&basicAuth,
//		&auth,
//	)
//	if err != nil {
//		return savedTeam, err
//	}
//
//	if basicAuth.Valid {
//		err = json.Unmarshal([]byte(basicAuth.String), &savedTeam.BasicAuth)
//		if err != nil {
//			return savedTeam, err
//		}
//	}
//
//	if auth.Valid {
//		err = json.Unmarshal([]byte(auth.String), &savedTeam.Auth)
//		if err != nil {
//			return savedTeam, err
//		}
//	}
//
//	return savedTeam, nil
//}
//
func (db *SQLDB) DeleteTeamByName(teamName string) error {
	var id sql.NullInt64
	err := db.conn.QueryRow(`
		SELECT id
		FROM teams
		WHERE LOWER(name) = LOWER($1)
	`, teamName).Scan(&id)
	if err != nil {
		return err
	}

	if !id.Valid {
		return errors.New("could-not-find-team-id")
	}

	tableDrop := fmt.Sprintf("DROP TABLE team_build_events_%d", id.Int64)

	_, err = db.conn.Exec(tableDrop)
	if err != nil {
		return err
	}

	_, err = db.conn.Exec(`
    DELETE FROM teams
		WHERE LOWER(name) = LOWER($1)
	`, teamName)
	return err
}
