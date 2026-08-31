from app.services import job_status


def test_record_and_read_last_run():
    job_status.record_run("test_job", "success")
    runs = job_status.all_last_runs()

    assert runs["test_job"]["outcome"] == "success"
    assert runs["test_job"]["at"] is not None


def test_recorded_timestamp_is_timezone_aware():
    # Naive isoformat() (no UTC offset) gets parsed as *local* time by a
    # browser's Date constructor -- see job_status.py's record_run comment.
    # A regression here silently breaks the dashboard's "Xs ago" readout.
    job_status.record_run("test_job", "success")
    assert job_status.all_last_runs()["test_job"]["at"].tzinfo is not None


def test_record_run_overwrites_previous_entry():
    job_status.record_run("test_job", "success")
    job_status.record_run("test_job", "failed")

    assert job_status.all_last_runs()["test_job"]["outcome"] == "failed"
