"""add user IDP id attribute

Revision ID: 2a69a8406f71
Revises: cf0c99c08578
Create Date: 2021-05-04 20:39:27.197143

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '2a69a8406f71'
down_revision = 'cf0c99c08578'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idp_id', sa.String(length=255), nullable=True, index=True, unique=True))

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('idp_id')
