const gplay = require('google-play-scraper');
const _ = require('lodash');
const fs = require('fs');
const Categories = require('./models/categories.js');

const collectionPath = './collection/';
const jsonFileExtension = '.json';
let collector = [];
let totalCollection = [];


getAllDataSet();

function getGooglePlayCollection(category) {
    gplay.list({
        category: category,
        collection: gplay.collection.TOP_FREE,
        num: 100,
        throttle: 10
    })
        .then((appDataResults) => {

            _.forEach(appDataResults, function (app) {
                collector.push({
                    appId: app.appId
                });
            });

            totalCollection = _.concat(totalCollection, collector);
            writeFile(category, collector);
            writeFile('TOTAL_COLLECTION', totalCollection);
        })
        .catch((err) => {
            console.log('getGooglePlayCollection() ERROR : ', err);
        });
}

function getAllDataSet() {
    // loops through the entire category model
    _.forEach(Categories, function (category) {
        getGooglePlayCollection(category);
    });
}

function writeFile(categoryName, data) {
    // converts the data collection to JSON format
    let stringifyCollection = JSON.stringify(data);
    // generates the file name using the category name
    let fileName = collectionPath + categoryName + jsonFileExtension;
    // creates json file for each category
    fs.writeFile(fileName, stringifyCollection, function (err, result) {
        if (err) {
            console.log('writeFile() ERROR : ', err);
        }
    });
    // clears collector holder
    collector = [];
}








