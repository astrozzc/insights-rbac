# Generated by Django 2.2.24 on 2022-03-02 21:49

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("api", "0010_explicitly_define_tenant_schema_name"),
    ]

    operations = [
        migrations.RenameField(model_name="tenant", old_name="schema_name", new_name="tenant_name",),
    ]