# 100mots

faire des tests pour les patients atteints d'Alzheimer, évaluer la conservation d'un microlexique

# To Do généraux:

faire un filtrage pour la visualisation des résultats: par ID utilisateur, par date
ajouter un mdp lors de la sélection du test pour que seul les patients légitimes puissent s'inscrire
ajouter le nom et le temps lors de la visu des résultats
enlever l'extension dans l'affichage des résultats
centrer les éléments, rendre tout plus joli, enlever les éléments de débug

faire un onglet entrainement (devinette, SFA ,répétition)

## Start App
lancer avec "python3 main.py"
attention à avoir copier le .env.template en .env 
anciennement on pouvait utiliser docker:
```
docker build -t destimbres:latest .
docker run -d -p 5000:5000 destimbres
```