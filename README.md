# 100mots

faire des tests pour les patients atteints d'Alzheimer, évaluer la conservation d'un microlexique

# To Do généraux:

finir l'envoi de mail (ou bien une autre façon d'envoyer les données à l'examinateur)
mettre une fonctionnalité de création de test par un utilisateur
permettre au patient de choisir son test

## Start App

```
docker build -t destimbres:latest .
docker run -d -p 5000:5000 destimbres
```