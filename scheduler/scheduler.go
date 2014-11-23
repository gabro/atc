package scheduler

import (
	"database/sql"

	"github.com/pivotal-golang/lager"

	"github.com/concourse/atc"
	"github.com/concourse/atc/builder"
	"github.com/concourse/atc/db"
	"github.com/concourse/turbine"
)

type SchedulerDB interface {
	ScheduleBuild(buildID int, serial bool) (bool, error)

	GetLatestInputVersions([]atc.InputConfig) (db.VersionedResources, error)

	GetJobBuildForInputs(job string, inputs []db.BuildInput) (db.Build, error)
	CreateJobBuildWithInputs(job string, inputs []db.BuildInput) (db.Build, error)

	GetNextPendingBuild(job string) (db.Build, []db.BuildInput, error)

	GetAllStartedBuilds() ([]db.Build, error)
}

type BuildFactory interface {
	Create(atc.JobConfig, atc.ResourceConfigs, []db.BuildInput) (turbine.Build, error)
}

type BuildTracker interface {
	TrackBuild(db.Build) error
}

type Scheduler struct {
	Logger  lager.Logger
	Locker  Locker
	DB      SchedulerDB
	Factory BuildFactory
	Builder builder.Builder
	Tracker BuildTracker
}

func (s *Scheduler) BuildLatestInputs(job atc.JobConfig, resources atc.ResourceConfigs) error {
	if len(job.Inputs) == 0 {
		// no inputs; no-op
		return nil
	}

	buildLog := s.Logger.Session("build-latest")

	lock, err := s.lockVersionUpdatesFor(job.Inputs)
	if err != nil {
		buildLog.Error("failed-to-acquire-inputs-lock", err)
		return err
	}

	versions, err := s.DB.GetLatestInputVersions(job.Inputs)

	lock.Release()

	if err != nil {
		buildLog.Error("failed-to-get-latest-input-versions", err)
		return err
	}

	inputs := []db.BuildInput{}
	for _, input := range job.Inputs {
		if !input.Trigger() {
			continue
		}

		vr, found := versions.Lookup(input.Resource)
		if !found {
			// this really shouldn't happen, but...
			buildLog.Error("failed-to-find-version", nil, lager.Data{
				"resource": input.Resource,
				"versions": versions,
			})
			continue
		}

		inputs = append(inputs, db.BuildInput{
			Name:              input.Name(),
			VersionedResource: vr,
		})
	}

	if len(inputs) == 0 {
		return nil
	}

	_, err = s.DB.GetJobBuildForInputs(job.Name, inputs)
	if err == nil {
		return nil
	}

	build, err := s.DB.CreateJobBuildWithInputs(job.Name, inputs)
	if err != nil {
		buildLog.Error("failed-to-create-build", err, lager.Data{
			"inputs": inputs,
		})
		return err
	}

	scheduled, err := s.DB.ScheduleBuild(build.ID, job.Serial)
	if err != nil {
		return err
	}

	if !scheduled {
		return nil
	}

	buildLog.Info("building", lager.Data{
		"build":  build,
		"inputs": inputs,
	})

	turbineBuild, err := s.Factory.Create(job, resources, inputs)
	if err != nil {
		buildLog.Error("failed-to-create", err)
		return err
	}

	err = s.Builder.Build(build, turbineBuild)
	if err != nil {
		buildLog.Error("failed-to-build", err)
		return err
	}

	return nil
}

func (s *Scheduler) TryNextPendingBuild(job atc.JobConfig, resources atc.ResourceConfigs) error {
	buildLog := s.Logger.Session("try-next-pending")

	build, inputs, err := s.DB.GetNextPendingBuild(job.Name)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}

		return err
	}

	scheduled, err := s.DB.ScheduleBuild(build.ID, job.Serial)
	if err != nil {
		return err
	}

	if !scheduled {
		return nil
	}

	turbineBuild, err := s.Factory.Create(job, resources, inputs)
	if err != nil {
		buildLog.Error("failed-to-create", err)
		return err
	}

	err = s.Builder.Build(build, turbineBuild)
	if err != nil {
		buildLog.Error("failed-to-build", err)
		return err
	}

	return nil
}

func (s *Scheduler) TriggerImmediately(job atc.JobConfig, resources atc.ResourceConfigs) (db.Build, error) {
	buildLog := s.Logger.Session("trigger-immediately")

	passedInputs := []atc.InputConfig{}
	for _, input := range job.Inputs {
		if len(input.Passed) == 0 {
			continue
		}

		passedInputs = append(passedInputs, input)
	}

	var inputs []db.BuildInput
	var err error

	if len(passedInputs) > 0 {
		versions, err := s.DB.GetLatestInputVersions(passedInputs)
		if err != nil {
			buildLog.Error("failed-to-get-build-inputs", err)
			return db.Build{}, err
		}

		for _, input := range job.Inputs {
			vr, found := versions.Lookup(input.Resource)
			if found {
				inputs = append(inputs, db.BuildInput{
					Name:              input.Name(),
					VersionedResource: vr,
				})
			}
		}
	}

	build, err := s.DB.CreateJobBuildWithInputs(job.Name, inputs)
	if err != nil {
		buildLog.Error("failed-to-create-build", err)
		return db.Build{}, err
	}

	scheduled, err := s.DB.ScheduleBuild(build.ID, job.Serial)
	if err != nil {
		return db.Build{}, err
	}

	if !scheduled {
		return build, nil
	}

	turbineBuild, err := s.Factory.Create(job, resources, inputs)
	if err != nil {
		buildLog.Error("failed-to-create", err)
		return db.Build{}, err
	}

	err = s.Builder.Build(build, turbineBuild)
	if err != nil {
		buildLog.Error("failed-to-build", err)
		return db.Build{}, err
	}

	return build, nil
}

func (s *Scheduler) TrackInFlightBuilds() error {
	builds, err := s.DB.GetAllStartedBuilds()
	if err != nil {
		return err
	}

	for _, b := range builds {
		go s.Tracker.TrackBuild(b)
	}

	return nil
}

func (s *Scheduler) lockVersionUpdatesFor(inputs []atc.InputConfig) (db.Lock, error) {
	locks := []db.NamedLock{}
	for _, input := range inputs {
		locks = append(locks, db.ResourceLock(input.Resource))
	}

	return s.Locker.AcquireReadLock(locks)
}
