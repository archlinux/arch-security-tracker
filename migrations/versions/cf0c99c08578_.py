"""Audit log

Revision ID: cf0c99c08578
Revises:
Create Date: 2017-12-12 21:12:56.282095

"""
from datetime import datetime

from alembic import op
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy_continuum import version_class
from sqlalchemy_continuum import versioning_manager
from sqlalchemy_continuum.operation import Operation

from tracker import db
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage

# revision identifiers, used by Alembic.
revision = 'cf0c99c08578'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ensure new transaction/version tables exist
    db.create_all()

    # update CVE table
    op.add_column('cve',
                  Column('created',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))
    op.add_column('cve',
                  Column('changed',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))

    for cve in CVE.query.all():
        cve.created = datetime.utcnow()
        cve.changed = cve.created

    db.session.commit()
    db.session.flush()

    # update AVG table
    op.add_column('cve_group',
                  Column('changed',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))

    for group in CVEGroup.query.all():
        group.changed = group.created

    db.session.commit()
    db.session.flush()

    VersionClassGroup = version_class(CVEGroup)
    uow = versioning_manager.unit_of_work(db.session)
    uow.create_transaction(db.session)

    for group in VersionClassGroup.query.all():
        for package in CVEGroupPackage.query.filter(
                CVEGroupPackage.group_id == group.id).all():
            package_version = uow.get_or_create_version_object(package)
            package_version.group_id = group.id
            package_version.pkgname = package.pkgname
            package_version.transaction_id = group.transaction_id
            package_version.end_transaction_id = group.end_transaction_id
            package_version.operation_type = Operation.INSERT
            package_version.group_id_mod = 1
            package_version.pkgname_mod = 1
            uow.process_operation(Operation(package, Operation.INSERT))

        for cve in CVEGroupEntry.query.filter(
                CVEGroupEntry.group_id == group.id).all():
            cve_version = uow.get_or_create_version_object(cve)
            cve_version.group_id = group.id
            cve_version.cve_id = cve.cve_id
            cve_version.transaction_id = group.transaction_id
            cve_version.end_transaction_id = group.end_transaction_id
            cve_version.operation_type = Operation.INSERT
            cve_version.group_id_mod = 1
            cve_version.cve_id_mod = 1
            uow.process_operation(Operation(cve, Operation.INSERT))

    uow.make_versions(db.session)
    db.session.commit()
    db.session.flush()

    with op.batch_alter_table('cve_group', schema=None) as batch_op:
        batch_op.alter_column('changed', nullable=False)

    # update advisory table
    op.add_column('advisory',
                  Column('changed',
                         DateTime,
                         default=datetime.utcnow,
                         nullable=True,
                         index=True))

    for advisory in Advisory.query.all():
        advisory.changed = group.created

    db.session.commit()
    db.session.flush()

    with op.batch_alter_table('advisory', schema=None) as batch_op:
        batch_op.alter_column('changed', nullable=False)

    # set all fields to modified for initial insert
    VersionClassCVE = version_class(CVE)
    VersionClassCVE.query.update({
        VersionClassCVE.operation_type: Operation.INSERT,
        VersionClassCVE.issue_type_mod: 1,
        VersionClassCVE.description_mod: 1,
        VersionClassCVE.severity_mod: 1,
        VersionClassCVE.remote_mod: 1,
        VersionClassCVE.reference_mod: 1,
        VersionClassCVE.notes_mod: 1
    })
    VersionClassGroup = version_class(CVEGroup)
    VersionClassGroup.query.update({
        VersionClassGroup.operation_type: Operation.INSERT,
        VersionClassGroup.status_mod: 1,
        VersionClassGroup.severity_mod: 1,
        VersionClassGroup.affected_mod: 1,
        VersionClassGroup.fixed_mod: 1,
        VersionClassGroup.bug_ticket_mod: 1,
        VersionClassGroup.reference_mod: 1,
        VersionClassGroup.notes_mod: 1,
        VersionClassGroup.created_mod: 1,
        VersionClassGroup.changed_mod: 1,
        VersionClassGroup.advisory_qualified_mod: 1
    })
    VersionClassAdvisory = version_class(Advisory)
    VersionClassAdvisory.query.update({
        VersionClassAdvisory.operation_type: Operation.INSERT,
        VersionClassAdvisory.group_package_id_mod: 1,
        VersionClassAdvisory.advisory_type_mod: 1,
        VersionClassAdvisory.publication_mod: 1,
        VersionClassAdvisory.workaround_mod: 1,
        VersionClassAdvisory.impact_mod: 1,
        VersionClassAdvisory.content_mod: 1,
        VersionClassAdvisory.created_mod: 1,
        VersionClassAdvisory.changed_mod: 1,
        VersionClassAdvisory.reference_mod: 1
    })
    db.session.commit()


def downgrade():
    with op.batch_alter_table('cve', schema=None) as batch_op:
        batch_op.drop_index('ix_cve_created')
        batch_op.drop_index('ix_cve_changed')
        batch_op.drop_column('created')
        batch_op.drop_column('changed')

    with op.batch_alter_table('cve_group', schema=None) as batch_op:
        batch_op.drop_index('ix_cve_group_changed')
        batch_op.drop_column('changed')

    with op.batch_alter_table('advisory', schema=None) as batch_op:
        batch_op.drop_index('ix_advisory_changed')
        batch_op.drop_column('changed')

    def drop(model):
        model.__table__.drop(db.engine)

    drop(version_class(CVE))
    drop(version_class(CVEGroup))
    drop(version_class(CVEGroupEntry))
    drop(version_class(CVEGroupPackage))
    drop(version_class(Advisory))
    drop(versioning_manager.transaction_cls)

    db.session.commit()
