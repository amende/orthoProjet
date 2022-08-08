# 100mots

faire des tests pour les patients atteints d'Alzheimer, évaluer la conservation d'un microlexique

# To Do généraux:

finir l'envoi de mail (ou bien une autre façon d'envoyer les données à l'examinateur)
pas le mail: utiliser un compte admin qui aura accès aux données
mettre une fonctionnalité de création de test par un utilisateur
permettre au patient de choisir son test
faire une gestion des chemins plus propres : avec une base comme


cheminSauvegarde = os.path.join(app.config['UPLOAD_FOLDER'], randomName)


## Start App
lancer avec "python3 main.py"
attention à avoir copier le .env.template en .env 
anciennement on pouvait utiliser docker:
```
docker build -t destimbres:latest .
docker run -d -p 5000:5000 destimbres
```