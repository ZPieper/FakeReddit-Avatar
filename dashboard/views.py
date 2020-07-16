from django.shortcuts import render, redirect
from home.models import User
from .models import Post
# Create your views here.
def dashboard(request):
    if 'user_id' not in request.session:
        return redirect('/')
    context = {
        'user': User.objects.get(id=request.session['user_id']),
        'posts': Post.objects.all()
    }
    return render(request, 'dashboard/index.html', context)

def delete(request, post_id):
    # i want to delete a post!
    # check that the post i'm about to delete belongs to the logged in user
    to_delete = Post.objects.get(id=post_id)
    if to_delete.author_id == request.session['user_id']:
        to_delete.delete()
    return redirect('/posts')