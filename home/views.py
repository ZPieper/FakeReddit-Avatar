from django.shortcuts import render, redirect
from django.contrib import messages
from .models import User
import bcrypt
# Create your views here.

def index(request):
    context = {
        'users': User.objects.get_all_by_username()
    }
    return render(request, 'index.html', context)

def create(request):
    # something is there for first_name!
    errors = User.objects.validate(request.POST)
    # are there errors?
    if errors:
        for field, value in errors.items():
            messages.error(request, value, extra_tags='register')
        return redirect('/')

    #TODO: hash users password before storing in the DB
    new_user = User.objects.register(request.POST, request.FILES)
    request.session['user_id'] = new_user.id
    return redirect('/posts')

def login(request):
    result = User.objects.authenticate(request.POST['username'], request.POST['password'])
    if result == False:
        messages.error(request, "Invalid Username/Password", extra_tags='login')
    else:
        user = User.objects.get(username=request.POST['username'])
        request.session['user_id'] = user.id
        return redirect('/posts')
    return redirect('/')

def show(request, user_id):
    print(user_id, "is user id!")
    # user profile page
    # prevent user not found!
    # [user] or []
    users_with_user_id = User.objects.filter(id=user_id)
    if len(users_with_user_id) < 1:
        # no user found with this id!
        return redirect('/')
    context = {
        'user': User.objects.get(id=user_id)
    }
    return render(request, 'show.html', context)

def success(request):
    # only logged in users should be here!
    if not 'user_id' in request.session:
        return redirect('/')
    context = {
        'user': User.objects.get(id=request.session['user_id'])
    }
    return render(request, 'success.html', context)

def logout(request):
    request.session.clear()
    
    return redirect('/')