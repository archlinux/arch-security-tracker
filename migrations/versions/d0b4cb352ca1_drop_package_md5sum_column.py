"""drop package.md5sum column

Revision ID: d0b4cb352ca1
Revises: 2a69a8406f71
Create Date: 2024-03-25 10:09:20.603755

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd0b4cb352ca1'
down_revision = '2a69a8406f71'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('package', schema=None) as batch_op:
        batch_op.drop_column('md5sum')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('package', schema=None) as batch_op:
        batch_op.add_column(sa.Column('md5sum', sa.VARCHAR(length=32), nullable=False))

    # ### end Alembic commands ###
