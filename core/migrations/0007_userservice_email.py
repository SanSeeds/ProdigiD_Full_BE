# Generated by Django 5.0.6 on 2024-08-11 13:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_userservice'),
    ]

    operations = [
        migrations.AddField(
            model_name='userservice',
            name='email',
            field=models.EmailField(blank=True, max_length=254),
        ),
    ]
