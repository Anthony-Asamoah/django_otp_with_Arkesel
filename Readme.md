## setup
Once the repo is cloned, run the ff commands:
- $ py manage.py makemigrations
- $ py manage.py migrate
- $ py manage.py createsuperuser 
  - provide details as required
- $ py manage.py runserver


## views
apart from djoser and simplejwt views/endpoints, there are two views defined in core.views.py.
this is where all the action happens.

- create otp: GET
```
 just as the name says, it generates an otp and sends out an sms using the ArkeselDevice.
```

- verify otp: POST
```
as the name implies, it vreifies a given code.
currently is not able to verify, returns false for everything
```

### Arkesel Device works using the ff files
```
.env
conf.py
admin.py
models.py
```
- conf.py holds configurations for the ArkeselDevice; derived from .env
- admin.py displays the device in django admin (used to manage devices)
- models.py creates the ArkeselDevice itself. this is where actual code to generate otp, verify otp & send the sms, can be found