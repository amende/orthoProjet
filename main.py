from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_talisman import Talisman
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from os import listdir
from os.path import isfile, join
import bcrypt
import random
import string
import os
import datetime
#import smtplib, ssl

# local files:
from models import User, Stamp, Exchange, Message, TestResult, VisuTest, db


# Load environment variables
load_dotenv()

PATH_TO_TESTS="/home/100mots/orthoProjet/static/images/tests/"
RELATIVE_PATH_TO_TESTS="/static/images/tests/"
debug = "TRUE"
secret_key = "pleasereplacebyrandomshit"
db_uri = 'sqlite:///db.sqlite3'
UPLOAD_FOLDER='./static/images/upload/'
ADMIN_NAME='admin'
ADMIN_PASSWORD='admin'
ADMIN_MAIL="admin@admin"
TEST_ACCESS_PASSWORD='access'

# App initialisation
app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADMIN_NAME']=ADMIN_NAME
app.config['ADMIN_PASSWORD']=ADMIN_PASSWORD
app.config['RELATIVE_PATH_TO_TESTS'] = RELATIVE_PATH_TO_TESTS

# gestion des upload images des timbres
app.config['UPLOAD_FOLDER'] ='./static/images/upload/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# CSP Policy
csp = {
    'default-src': '\'self\' data:',
    'script-src': '\'self\'',
    'style-src': '\'self\' https://fonts.googleapis.com/',
    'font-src': '\'self\' data: fonts.gstatic.com/',
}
Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['style-src', 'script-src'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.after_request
def protect_response(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


# Database initialisation
db.init_app(app)



with app.app_context():
    # db.drop_all()
    db.create_all()
    


# CSRF protection
csrf = CSRFProtect()
csrf.init_app(app)





# Login manager initialisation
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


#code pour accéder au répertoire des tests, mais ça fonctionne po :/
"""
@app.route('/tests/<path:filename>')
@login_required
def uploaded_file(path="",filename=""):
    return send_from_directory(app.config['RELATIVE_PATH_TO_TESTS']+path,
                               filename)

"""
@app.route('/')
def home():
    return render_template('home.html', stampCount=Stamp.query.count())

"""

#protect the test file :
@app.route('/tests/<path:filename>')
@login_required
def noAccess(path=0,filename=0):
    return redirect(url_for('profile'))
"""


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', stampsUploaded=Stamp.query.filter_by(owner=current_user.id).count(),
                           stampsExchanged=Exchange.query.filter_by(senderID=current_user.id,accepted=True).count()
                           + Exchange.query.filter_by(receiverID=current_user.id,accepted=True).count())


@app.route('/signup')
def signup():
    if (User.query.filter_by(isAdmin=True).count()==0):
        admin = User(email=ADMIN_MAIL, name=ADMIN_NAME,
                                    password=bcrypt.hashpw(ADMIN_PASSWORD.encode('utf-8'), bcrypt.gensalt()),testFolder="premierTest",isAdmin=True)
        db.session.add(admin)                       
        db.session.commit()
    if current_user.is_authenticated:
        flash('You are already registered and signed in')
        return(redirect(url_for('profile')))
    else:
        return(render_template('signup.html'))


@app.route('/signup', methods=['POST'])
def signup_post():
    if current_user.is_authenticated:
        flash('You are already registered and signed in')
        return(redirect(url_for('profile')))
    else:
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if len(password) < 8:
            flash("Please choose a password at least 8 characters long.")
            return redirect(url_for("signup"))
        if len(name) < 3:
            flash("Please choose a username at least 4 characters long.")
            return redirect(url_for("signup"))

        user = User.query.filter_by(name=name).first()
        if user:
            flash("This username is already taken.")
            return(redirect(url_for('signup')))

        user = User.query.filter_by(email=email).first()
        if user:
            flash("An account already exists for this email.")
            return(redirect(url_for('signup')))

        new_user = User(email=email, name=name,
                        password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()),testFolder="premierTest/",isAdmin=False)
        db.session.add(new_user)
        db.session.commit()
        flash("Account has been created, now please login.")
        return redirect(url_for("login"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Successfully logged out")
    return render_template('home.html', stampCount=Stamp.query.count())


@app.route('/tandc')
def tandc():
    return render_template('tandc.html')


@app.route('/editProfile', methods=['POST'])
@login_required
def editProfile():
    notif_success = False

    name = request.form.get('name')
    if name != "":
        if len(name) < 3:
            flash("Please choose a username at least 4 characters long.")
            return redirect(url_for("profile"))
        current_user.name = name
        notif_success = True

    email = request.form.get('email')
    if email != "":
        current_user.email = email
        notif_success = True

    password = request.form.get('password')
    if password != "":
        if len(name) < 8:
            flash("Please choose a password at least 8 characters long.")
            return redirect(url_for("profile"))
        current_user.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        notif_success = True

    if notif_success:
        flash("Successfully edited profile")

    db.session.commit()
    return render_template('profile.html', stampsUploaded=Stamp.query.filter_by(owner=current_user.id).count(),
                           stampsExchanged=Exchange.query.filter_by(senderID=current_user.id,accepted=True).count()
                           + Exchange.query.filter_by(receiverID=current_user.id,accepted=True).count())


@app.route('/deleteProfile', methods=['GET', 'POST'])
@login_required
def deleteProfile():
    if request.method == 'GET':
        return render_template('confirmDeleteProfile.html')
    if request.method == 'POST':
        db.session.delete(User.query.filter_by(id=current_user.id).first())
        db.session.commit()
        logout_user()
        flash("Successfully deleted profile")
        return render_template('home.html', stampCount=Stamp.query.count())


@app.route('/login')
def login():
    if current_user.is_authenticated:
        flash('You are already signed in')
        return(redirect(url_for('profile')))
    else:
        return render_template('login.html')


@app.route('/login', methods=['POST'])
def login_post():
    if current_user.is_authenticated:
        flash('You are already signed in')
        return(redirect(url_for('profile')))
    else:
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Bad email/password combination')
            return(render_template('login.html'))

        if bcrypt.checkpw(password.encode('utf-8'), user.password):
            login_user(user)
            return(redirect(url_for('profile')))
        else:
            flash('Bad email/password combination')
            return(render_template('login.html'))



@app.route('/MakeTest')   ### cette page prépare le test : nombre d'images, prise au hasard des images
@login_required
def makeTest():
    #si c'est un refresh, refaire un test
    user=current_user
    userTestFolder=user.testFolder
    TestResult.query.filter_by(owner=user.id).delete()
    #db.session.commit()
    filenames = [ f for f in listdir(PATH_TO_TESTS+userTestFolder) if isfile(join(PATH_TO_TESTS+userTestFolder, f))]
    random.shuffle(filenames)
    strFiles=''
    for k in filenames:
        strFiles+=k
        strFiles+="::"
    
    new_test = TestResult(images=strFiles, owner = user.id,result=""
                        )
    db.session.add(new_test)
    db.session.commit()
    ##test
    #testResult=TestResult.query.filter_by(owner=user.id,testSent=False).first()
    #images=testResult.images      ,images=images
    return (render_template('makeTest.html',strFiles=strFiles))

@app.route('/testing', methods=['POST'])
@login_required
def testing():
    user = current_user
    testResult= TestResult.query.filter_by(owner=user.id).first()
    strFiles = request.form.get("strFiles")
    if request.form.get("action"):
        if request.form.get("action")=="correct":
            #ici ajouter un 1 au test result 
            testResult.result="1"+str(testResult.result)
        else:
            #et ici un 0
            testResult.result="0"+str(testResult.result)
        result=testResult.result
    else:
        #lancer un chrono
        testResult.time=datetime.datetime.now()
        result=""
    db.session.commit()
    chrono=testResult.time
    filenames =strFiles.split("::")
    nextPage="/testing"
    if len(filenames)==2:
        nextPage="/endTest"
    if filenames[-1]=="/":
        filenames.pop()
    imageTest=join(RELATIVE_PATH_TO_TESTS +user.testFolder, filenames.pop())
    strFiles=""
    for k in filenames:
        strFiles+=k
        strFiles+="::"
    return(render_template('testing.html', imageTest=imageTest,strFiles=strFiles, nextPage=nextPage,result=result,chrono=chrono))


@app.route('/endTest', methods=['POST'])
@login_required
def endTest():
    #finir le chrono
    userTestFolder=current_user.testFolder # à modifier en fonction du folder choisi par l'utilisateur
    user=current_user
    testResult= TestResult.query.filter_by(owner=user.id).first()
    if request.form.get("action")=="correct":
        #ici ajouter un 1 au test result 
        testResult.result="1"+str(testResult.result)
    else:
        #et ici un 0
        testResult.result="0"+str(testResult.result)
    seconds = (datetime.datetime.now()-testResult.time).total_seconds()
    totalTime=str(datetime.timedelta(seconds = seconds))
    #
    """
    #envoyer les résultats par mail :##########################
    port = 465  # For SSL
    emailPassword = "memoire67ortho"
    sender_email = "memoireortho67@gmail.com"  # Enter your address
    receiver_email = "memoireortho67@gmail.com"  # Enter receiver address
    message = 

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as server:
        server.login(sender_email, emailPassword)
        server.sendmail(sender_email, receiver_email, message)

    ###############################"""
    listeImages=str(testResult.images).split("::")
    if "" in listeImages:
        listeImages.remove("")
    mesImages=[]
    for k in listeImages:
        mesImages.append(str(k).removeprefix("images/tests/" + userTestFolder))
    listeResultats=list(str(testResult.result))

    listeDuo=[]
    for k in range(len(listeImages)):
        listeDuo.append((mesImages[k],listeResultats[k]))


    texteResultat=""
    for k in listeDuo:
        texteResultat+= k[0].split(".")[0]+","+k[1]+";"
    texteResultat+="end;"
    new_visu=VisuTest(visu=texteResultat,timeVisu="fait en "+totalTime+" le "+ datetime.now().date(),owner=user.id,admin=True)
    db.session.add(new_visu)
    TestResult.testSent=True
    db.session.delete(TestResult.query.filter_by(id=TestResult.id).first())
    db.session.commit()
    flash("Test terminé")
    return (render_template('endTest.html'))



@app.route('/ViewTests')
@login_required
def viewTests():
    #lister les répertoires:[x[0] for x in os.walk(os.getcwd())] 
    links=[x[0] for x in os.walk(PATH_TO_TESTS)]
    folderList=[]
    for k in links:
        folderList.append(k.removeprefix(PATH_TO_TESTS))
    if "" in folderList:
        folderList.remove("")
    return (render_template('viewTests.html', folderList=folderList))



@app.route('/SetTest',methods=['POST'])
@login_required
def setTest():
    if request.form.get("password")==TEST_ACCESS_PASSWORD:
        folder=request.form.get("folder")
        if folder=="":
            return redirect(url_for("viewTests"))
        user=current_user
        user.testFolder=folder
        db.session.commit()
        flash("Test sélectionné")
        return redirect(url_for("profile"))
    else:
        flash("MDP incorrect")
        return redirect(url_for("profile"))




######les taches de l'admin :



@app.route('/CreateTest')
@login_required
def createTest():
    if current_user.email != ADMIN_MAIL:
        return redirect(url_for('profile'))
    else:
        return (render_template('createTest.html'))


@app.route('/CreateTest', methods=['POST'])
@login_required
def createTest_post():
    if current_user.email != ADMIN_MAIL:
        return redirect(url_for('profile'))
    else:
        testName = request.form.get("testName")
        images = request.files.getlist("uploads")
        repertoire = PATH_TO_TESTS + testName
        if not os.path.exists(repertoire):
            os.makedirs(repertoire)
            for file in images:
                if allowed_file(file.filename):
                    chemin=os.path.join(repertoire, file.filename)
                    file.save(chemin)
        flash("Test créé")
        return redirect(url_for("profile"))


@app.route('/ViewResults', methods=['GET', 'POST'])
@login_required
def viewResults():
    if current_user.email != ADMIN_MAIL:
        return redirect(url_for('profile'))
    else:
        if request.method=="GET":
            listeTests = VisuTest.query.filter_by(admin=True)
            stringList=[]
            for k in listeTests:
                stringList.append("temps: "+str(k.timeVisu))
                user_name=User.query.filter_by(id=k.owner).first().name
                stringList.append("nom d'utilisateur: "+user_name)
                divisionListe=k.visu.split(";")
                for i in divisionListe:
                    stringList.append(i)
            return (render_template('viewResults.html',stringList=stringList))
        else:
            listeTests = VisuTest.query.filter_by(admin=True)
            stringList=[]
            for k in listeTests:
                user_name=User.query.filter_by(id=k.owner).first().name
                if user_name==request.form.get("username"):
                    stringList.append("temps: "+str(k.timeVisu))
                    stringList.append("nom d'utilisateur: "+user_name)
                    divisionListe=k.visu.split(";")
                    for i in divisionListe:
                        stringList.append(i)
            return (render_template('viewResults.html',stringList=stringList))

    

########################################################################################################################################################

#ancien code !!!!
# gestion de la collection:
"""

@app.route('/myCollec')
@login_required
def myCollec():
    user = current_user
    stamps = Stamp.query.filter_by(owner=user.id)
    return(render_template("myCollec.html", stamps=stamps))


@app.route('/addStamp', methods=['GET', 'POST'])
@login_required
def addStamp():
    if request.method == 'GET':
        return(render_template("addStamp.html"))
    if request.method == 'POST':
        # gestion de l'image
        if 'file' not in request.files:
            securedFileName = 'images/img_wireframe.png'
        else:
            file = request.files['file']
            if file.filename == '':
                securedFileName = 'images/img_wireframe.png'
            if file and allowed_file(file.filename):
                letters = string.ascii_lowercase
                randomName = ''.join(random.choice(letters) for i in range(15))
                securedFileName = 'images/upload/'+randomName
                cheminSauvegarde = os.path.join(app.config['UPLOAD_FOLDER'], randomName)
                file.save(cheminSauvegarde)
        # en bdd
        name = request.form.get('name')
        year = request.form.get('date')
        owner = current_user.id
        isPublic = request.form.get('isPublic') == 'on'
        new_stamp = Stamp(name=name, year=year, owner=owner, isPublic=isPublic, fileName=securedFileName)
        db.session.add(new_stamp)
        db.session.commit()
        return(redirect(url_for("myCollec")))


# Recherche de timbres
@app.route('/searchStamp', methods=['GET', 'POST'])
@login_required
def searchStamp():
    if request.method == 'GET':
        stamps = Stamp.query.filter_by(isPublic=True).limit(50)
        stamps = [(stamp,User.query.filter_by(id=stamp.owner).first().name) for stamp in stamps]

        return(render_template("search.html", stamps=stamps))
    if request.method == 'POST':
        min_year = request.form.get('min_year')
        if min_year == "":
            min_year = 0

        max_year = request.form.get('max_year')
        if max_year == "":
            max_year = 3000

        name = request.form.get('name')

        stamps = Stamp.query.filter(Stamp.name.ilike('%'+name+'%'))   \
                            .filter(Stamp.year >= min_year, Stamp.year <= max_year)   \
                            .filter_by(isPublic=True).limit(50)

        stamps = [(stamp,User.query.filter_by(id=stamp.owner).first().name) for stamp in stamps]

        return(render_template("search.html", stamps=stamps))


@app.route('/exchange')
@login_required
def exchange():
    idwanted = request.args.get('wanted')
    if idwanted:  # if we are coming from the search page
        hisStamp = Stamp.query.filter_by(id=idwanted).first()
        if hisStamp.isPublic:
            stamps = Stamp.query.filter_by(owner=current_user.id, isPublic=True)
            return(render_template('exchange.html', stamps=stamps, hisStamp=hisStamp))
    else:
        exchanges = Exchange.query.filter_by(receiverID=current_user.id, answered=False)
        exchanges = [{"id": ex.id,
                      "senderName": User.query.filter_by(id=ex.senderID).first().name,
                      "stampSent": Stamp.query.filter_by(id=ex.senderStampID).first(),
                      "stampReceived": Stamp.query.filter_by(id=ex.receiverStampID).first()}
                     for ex in exchanges]
        print(exchanges)
        return(render_template('pendingExchanges.html', exchanges=exchanges))


@app.route('/AcceptExchange', methods=['POST'])
@login_required
def AcceptExchange():
    # validation
    if not(request.form['accept'] == 'yes' or request.form['accept'] == 'no')   \
           or 'exchangeid' not in request.form  \
           or Exchange.query.filter_by(id=request.form["exchangeid"]).first().receiverID != current_user.id \
           or Exchange.query.filter_by(id=request.form["exchangeid"]).first().answered:
        flash("Something went terribly wrong. Try again or report to the adminstrator.")
        return(redirect(url_for("exchange")))
    accepted = request.form['accept'] == 'yes'
    exchange = Exchange.query.filter_by(id=request.form["exchangeid"]).first()
    myStamp = Stamp.query.filter_by(id=exchange.receiverStampID).first()
    hisStamp = Stamp.query.filter_by(id=exchange.senderStampID).first()
    timestamp = datetime.datetime.now()
    if accepted:
        myStamp.owner = exchange.senderID
        hisStamp.owner = exchange.receiverID
        exchange.accepted = True
    exchange.answered = True
    db.session.commit()
    flash("Exchange accepted" if accepted else "Exchange refused")
    sender = current_user.id
    seen = False
    new_message = Message(timestamp=timestamp, sender=sender, receiver=exchange.senderID,
                          content="I accepted your exchange" if accepted else
                                  "I refused your exchange", seen=seen)
    db.session.add(new_message)
    db.session.commit()
    return(redirect(url_for("exchange")))


@app.route('/confirmExchange', methods=['GET', 'POST'])
@login_required
def confirmExchange():
    if request.method == 'GET':
        mystampid = request.args.get("MyStamp")
        hisstampid = request.args.get("HisStamp")
        return(render_template('confirmExchange.html', mystampid=mystampid, hisstampid=hisstampid))
    if request.method == 'POST':
        mystampid = request.form["MyStamp"]
        hisstampid = request.form["HisStamp"]
        hisStamp = Stamp.query.filter_by(id=int(hisstampid)).first()
        myStamp = Stamp.query.filter_by(id=int(mystampid)).first()
        idSender = current_user.id
        idReceiver = hisStamp.owner
        if myStamp.isPublic and hisStamp.isPublic:
            if not(Exchange.query.filter_by(senderStampID=myStamp.id, answered=False).first()) \
               and not(Exchange.query.filter_by(senderStampID=myStamp.id, answered=False).first()):
                if not(Exchange.query.filter_by(receiverStampID=myStamp.id, answered=False).first()) \
                   and not(Exchange.query.filter_by(receiverStampID=myStamp.id, answered=False).first()):
                    new_exchange = Exchange(senderID=idSender, receiverID=idReceiver, receiverStampID=hisStamp.id,
                                            senderStampID=myStamp.id, answered=False, accepted=False)
                    db.session.add(new_exchange)
                    db.session.commit()
                    flash("Exchange request sent")
                else:
                    flash("The stamp you want is already part of a pending exchange.")
            else:
                flash("The stamp you want to give is already part of a pending exchange.")
        else:
            flash("Either the stamp you give or the one you want is not public or doesn't exist")
        return(redirect(url_for("profile")))


# Message
@app.route('/messaging', methods=['GET', 'POST'])
@login_required
def messaging():

    if request.method == 'POST':
        if request.form.get("action") == "postMessage":
            timestamp = datetime.datetime.now()
            sender = current_user.id
            receiver = User.query.filter_by(name=request.form.get('receiver')).first()
            if receiver is not None:
                receiver = receiver.id
                content = request.form.get('content')
                if len(content) <= 140:
                    seen = False
                    new_message = Message(timestamp=timestamp, sender=sender, receiver=receiver,
                                          content=content, seen=seen)
                    db.session.add(new_message)
                    db.session.commit()
                else:
                    flash("Message too long.")
            else:
                flash("User not found.")

    # Getting received messages
    messagesReceivedQuery = Message.query.filter_by(receiver=current_user.id)
    messagesReceived = []

    for message in messagesReceivedQuery:
        date = f"{message.timestamp:%Y/%m/%d %H:%M}"
        sender = User.query.filter_by(id=message.sender).first().name
        receiver = User.query.filter_by(id=message.receiver).first().name
        content = message.content
        seen = "Yes" if message.seen else "No"
        if not(message.seen):
            message.seen = True
            db.session.commit()
        messagesReceived.append({"id": message.id, "date": date, "sender": sender, "receiver": receiver,
                                 "sender_id": message.sender, "receiver_id": message.receiver,
                                 "content": content, "seen": seen})

    # Getting sent messages
    messagesSentQuery = Message.query.filter_by(sender=current_user.id)
    messagesSent = []

    for message in messagesSentQuery:
        date = f"{message.timestamp:%Y/%m/%d %H:%M}"
        sender = User.query.filter_by(id=message.sender).first().name
        receiver = User.query.filter_by(id=message.receiver).first().name
        content = message.content
        seen = "Yes" if message.seen else "No"
        messagesSent.append({"id": message.id, "date": date, "sender": sender, "receiver": receiver,
                             "sender_id": message.sender, "receiver_id": message.receiver,
                             "content": content, "seen": seen})

    messages = messagesReceived+messagesSent
    messages.sort(key=lambda x: x["date"], reverse=True)
    return(render_template("messaging.html", messagesReceived=messagesReceived, messagesSent=messagesSent,
                           messages=messages))




    """
########################################################################


@login_required
def get_message_number():
    messagesNotSeen = Message.query.filter_by(receiver=current_user.id, seen=False).all()
    return len(messagesNotSeen)

app.jinja_env.globals.update(get_message_number=get_message_number)



# Start development web server
if __name__ == '__main__':
    #app.run()
    app.run(host='0.0.0.0', port=5000, debug=True)
