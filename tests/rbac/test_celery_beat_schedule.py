#
# Copyright 2024 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Tests for Celery beat schedule selection logic."""

import importlib
from unittest.mock import patch

from celery.schedules import crontab
from django.test import TestCase, override_settings


class TestBeatSchedulePrincipalCleanup(TestCase):
    """Verify the beat schedule selects the correct principal cleanup task based on settings."""

    def _reload_celery_schedule(self):
        """Reload the celery module to re-evaluate schedule selection."""
        import rbac.celery as celery_module

        importlib.reload(celery_module)
        return celery_module.app.conf.beat_schedule

    @override_settings(KAFKA_PRINCIPAL_CLEANUP_JOB_ENABLED=True, KAFKA_PRINCIPAL_CLEANUP_TOPIC="test-topic")
    def test_kafka_enabled_and_topic_set_schedules_kafka_task(self):
        """When both JOB_ENABLED and TOPIC are set, the 60s Kafka task is scheduled."""
        schedule = self._reload_celery_schedule()
        self.assertIn("principal-cleanup-every-minute", schedule)
        self.assertEqual(
            schedule["principal-cleanup-every-minute"]["task"], "management.tasks.principal_cleanup_via_kafka"
        )
        self.assertEqual(schedule["principal-cleanup-every-minute"]["schedule"], 60)
        self.assertNotIn("principal-cleanup-every-sevenish-days", schedule)

    @override_settings(KAFKA_PRINCIPAL_CLEANUP_JOB_ENABLED=True, KAFKA_PRINCIPAL_CLEANUP_TOPIC="")
    def test_kafka_enabled_but_no_topic_falls_back_to_sweep(self):
        """When JOB_ENABLED is True but TOPIC is empty, the 7-day sweep is scheduled instead."""
        schedule = self._reload_celery_schedule()
        self.assertIn("principal-cleanup-every-sevenish-days", schedule)
        self.assertEqual(
            schedule["principal-cleanup-every-sevenish-days"]["task"], "management.tasks.principal_cleanup"
        )
        self.assertEqual(
            schedule["principal-cleanup-every-sevenish-days"]["schedule"],
            crontab(0, 0, day_of_month="7-28/7"),
        )
        self.assertNotIn("principal-cleanup-every-minute", schedule)

    @override_settings(KAFKA_PRINCIPAL_CLEANUP_JOB_ENABLED=False, KAFKA_PRINCIPAL_CLEANUP_TOPIC="test-topic")
    def test_kafka_disabled_falls_back_to_sweep(self):
        """When JOB_ENABLED is False (even with a topic), the 7-day sweep is scheduled."""
        schedule = self._reload_celery_schedule()
        self.assertIn("principal-cleanup-every-sevenish-days", schedule)
        self.assertEqual(
            schedule["principal-cleanup-every-sevenish-days"]["schedule"],
            crontab(0, 0, day_of_month="7-28/7"),
        )
        self.assertNotIn("principal-cleanup-every-minute", schedule)

    @override_settings(KAFKA_PRINCIPAL_CLEANUP_JOB_ENABLED=False, KAFKA_PRINCIPAL_CLEANUP_TOPIC="")
    def test_both_disabled_falls_back_to_sweep(self):
        """When both are off/empty, the 7-day sweep is scheduled."""
        schedule = self._reload_celery_schedule()
        self.assertIn("principal-cleanup-every-sevenish-days", schedule)
        self.assertEqual(
            schedule["principal-cleanup-every-sevenish-days"]["schedule"],
            crontab(0, 0, day_of_month="7-28/7"),
        )
        self.assertNotIn("principal-cleanup-every-minute", schedule)
