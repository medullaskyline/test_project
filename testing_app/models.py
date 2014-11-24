from django.db import models
from django.template.defaultfilters import slugify
from django.contrib.auth.models import User

from django.contrib import admin
from oauth2client.django_orm import FlowField, CredentialsField


class Category(models.Model):
    name = models.CharField(max_length=128, unique=True)
    views = models.IntegerField(default=0)
    likes = models.IntegerField(default=0)
    slug = models.SlugField(unique=True, default='')

    def save(self, *args, **kwargs):
        self.slug = slugify(self.name)
        super(Category, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name_plural = "Categories"


class Page(models.Model):
    category = models.ForeignKey(Category)
    title = models.CharField(max_length=128)
    url = models.URLField()
    views = models.IntegerField(default=0)

    def __unicode__(self):
        return self.title


# from https://developers.google.com/api-client-library/python/guide/django
# Use the oauth2client.django_orm.FlowField class as a Django model field so
# that Flow objects can easily be stored. When your application is simultaneously
# going through OAuth 2.0 steps for many users, it's normally best to store
# per-user Flow objects before the first redirection. This way, your redirection
# handlers can retrieve the Flow object already created for the user.
# In the following code, a model is defined that allows Flow objects to be stored and keyed by User:
class FlowModel(models.Model):
    id = models.ForeignKey(User, primary_key=True)
    flow = FlowField()


# Use the oauth2client.django_orm.CredentialsField class as a Django model field
# so that Credentials objects can easily be stored. Similar to Flow objects, it's
# normally best to store per-user Credentials objects. In the following code, a model
# is defined that allows Credentials objects to be stored and keyed by User:
class CredentialsModel(models.Model):
    id = models.ForeignKey(User, primary_key=True)
    credential = CredentialsField()


class UserProfile(models.Model):
    # This line is required. Links UserProfile to a User model instance.
    user = models.OneToOneField(User)

    # The additional attributes we wish to include.
    website = models.URLField(blank=True)
    picture = models.ImageField(upload_to='profile_images', blank=True)

    # Override the __unicode__() method to return out something meaningful!
    def __unicode__(self):
        return self.user.username