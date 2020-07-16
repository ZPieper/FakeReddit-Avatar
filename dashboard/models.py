from django.db import models
from home.models import User

class PostManager(models.Manager):
    def validate(self, post_data):
        errors = {}
        # title has to be not empty
        if len(post_data['title']) < 1:
            errors['title'] = "title has to be not empty"
        # content has to be at least 5 characters
        if len(post_data['content']) < 5:
            errors['content'] = "Content has to be at least 5 characters"

        return errors
# Create your models here.
class Post(models.Model):
    title = models.CharField(max_length=255)
    content = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # author_id
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name="posts")