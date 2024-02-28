// top cpc
var data_cpc = window.get_cpc_counts_from_db;
const labels_cpc = Object.keys(data_cpc);
const colors_cpc = generateRandomColors(labels_cpc.length);
const chartDatasets_cpc = [{
    label: '',
    backgroundColor: colors_cpc,
    data: Object.values(data_cpc),
}];

var ctx = document.getElementById("horizontal-stacker-bar-chart_cpc").getContext('2d');
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: labels_cpc,
        datasets: chartDatasets_cpc,
    },
    options: {
        tooltips: {
            displayColors: true,
            callbacks: {
                mode: 'x',
            },
        },
        scales: {
            x: {
                stacked: true,
            },
            y: {
                stacked: true,
            },
        },
        indexAxis: 'y',
        responsive: true,
    },
});
// top cpc

// top ipc
var data = window.get_ipc_counts;
const labels = Object.keys(data);
const colors = generateRandomColors(labels.length);
// Create datasets array for Chart.js
const chartDatasets = [{
    label: '',
    backgroundColor: colors,
    data: Object.values(data),
}];

var ctx = document.getElementById("horizontal-stacker-bar-chart").getContext('2d');
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: labels,
        datasets: chartDatasets,
    },
    options: {
        tooltips: {
            displayColors: true,
            callbacks: {
                mode: 'x',
            },
        },
        scales: {
            x: {
                stacked: true,
            },
            y: {
                stacked: true,
            },
        },
        indexAxis: 'y',
        responsive: true,
    },
});
// top ipc
// Function to generate random colors
function generateRandomColors(count) {
    const randomColors = [];
    for (let i = 0; i < count; i++) {
        randomColors.push(`rgba(${Math.floor(Math.random() * 256)}, ${Math.floor(Math.random() * 256)}, ${Math.floor(Math.random() * 256)}, 0.8)`);
    }
    return randomColors;
}

var year_wise_exp_date = window.yearWiseExpDate;
const xValues = Object.keys(year_wise_exp_date).map(Number);
const yValues = Object.values(year_wise_exp_date);

new Chart("myChart", {
    type: "line",
    data: {
        labels: xValues,
        datasets: [{
            fill: false,
            lineTension: 0,
            backgroundColor: "rgba(0,0,255,1.0)",
            borderColor: "rgba(0,0,255,0.1)",
            data: yValues
        }]
    },
    options: {
        legend: {
            display: false
        },
        scales: {
            yAxes: [{
                ticks: {
                    min: Math.min(...yValues),
                    max: Math.max(...yValues) + 1
                }
            }],
        }
    }
});
$(function() {
var areaChartCanvas = $('#areaChart').get(0).getContext('2d');
var labels = Object.keys(year_wise_count);
var data = Object.values(year_wise_count);
var areaChartData = {
    labels: labels,
    datasets: [{
        label: 'Year-wise Count',
        backgroundColor: 'rgba(60,141,188,0.9)',
        borderColor: 'rgba(60,141,188,0.8)',
        pointRadius: false,
        pointColor: '#3b8bba',
        pointStrokeColor: 'rgba(60,141,188,1)',
        pointHighlightFill: '#fff',
        pointHighlightStroke: 'rgba(60,141,188,1)',
        data: data
    }]
};

var areaChartOptions = {
    maintainAspectRatio: false,
    responsive: true,
    legend: {
        display: false
    },
    scales: {
        xAxes: [{
            gridLines: {
                display: false,
            }
        }],
        yAxes: [{
            gridLines: {
                display: false,
            }
        }]
    }
};

var areaChart = new Chart(areaChartCanvas, {
    type: 'line',
    data: areaChartData,
    options: areaChartOptions
});

var tableVisible = false;
areaChartCanvas.canvas.addEventListener('click', function (event) {
    if (!tableVisible) {
        var sortedData = labels.map(function (label, index) {
            return { label: label, value: data[index] };
        }).sort(function (a, b) {
            return b.value - a.value;
        }).slice(0, 10);
        var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Year</th><th>Count</th></tr>';
        sortedData.forEach(function (entry) {
            tableContent += '<tr><td>' + entry.label + '</td><td>' + entry.value + '</td></tr>';
        });
        tableContent += '</table>';
        tableContent += '<div style="text-align: center; margin-top: 10px;">';
        tableContent += '<button id="okButton">Ok</button>';
        tableContent += '<button id="downloaareadButton">Download</button>';
        tableContent += '</div>';
        $('<div></div>').html(tableContent).dialog({
            title: 'Top Ten Year-wise Counts',
            modal: true,
            position: {
                my: 'left top',
                at: 'left+10 top+10',
                of: event,
                collision: 'fit'
            },
            close: function () {
                tableVisible = false;
                $(this).dialog('destroy').remove();
            }
        });
        tableVisible = true;
        $('#okButton').on('click', function () {
            $(this).closest('.ui-dialog-content').dialog('close');
        });

        $('#downloaareadButton').on('click', function () {
            downloadareaExcelFile();
        });
    }
});

function downloadareaExcelFile() {
    var user_id = window.user_id;
    fetch("/get_year_wise_excel/", {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.blob();
    })
    .then(blob => {
        var link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = 'year wise publication count.xlsx';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(error => console.error('Error:', error));
}
    //-------------
    //- LINE CHART -
    //--------------
    var country_code_counts = window.country_code_counts;
    var lineChartCanvas = $('#lineChart').get(0).getContext('2d');
    var lineChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        scales: {
            x: {
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Country Code',
                },
            },
            y: {
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Top Innovative Jurisdiction',
                },
            },
        },
    };

    var lineChartData = {
        labels: Object.keys(country_code_counts),
        datasets: [{
            label: 'Top Innovative Jurisdiction',
            borderColor: 'rgba(60,141,188,0.9)',
            pointRadius: false,
            pointColor: '#3b8bba',
            pointStrokeColor: 'rgba(60,141,188,1)',
            pointHighlightFill: '#fff',
            pointHighlightStroke: 'rgba(60,141,188,1)',
            data: Object.values(country_code_counts),
        }],
    };

    lineChartData.datasets[0].fill = false;
    lineChartOptions.datasetFill = false;

    var lineChart = new Chart(lineChartCanvas, {
        type: 'line',
        data: lineChartData,
        options: lineChartOptions,
    });
    //  for table
    // Ensure tableVisible is properly initialized
    // Ensure tableVisible is properly initialized
var tableVisible = false;

// Assuming 'lineChart' is an HTML element like a button
var lineChartElement = document.getElementById('lineChart');

lineChartElement.addEventListener('click', function () {
    if (!tableVisible) {
        var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Patent</th><th>Citations</th></tr>';
        tableContent += '<tr><td>' + 'dfgvdf' + '</td><td>' + 'dtgbtbhg' + '</td></tr>';
        tableContent += '</table>';

        var buttons = {
            Ok: function () {
                $(this).dialog('close');
                tableVisible = false;
            }
        };

        $('<div></div>').html(tableContent).dialog({
            title: 'All Patents Details',
            modal: true,
            buttons: buttons,
            close: function () {
                tableVisible = false;
            }
        });

        tableVisible = true;
    }
});

//  for table
//-------------
//- DONUT CITED CHART -
//-------------
var donutChartCanvas_cited = $('#donut_cited_Chart').get(0).getContext('2d');
var keys_cited = Object.keys(topCitedPatentsDict_cited);
var values_cited = Object.values(topCitedPatentsDict_cited);
var tableVisible = false;
var donutData_cited = {
    labels: keys_cited,
    datasets: [{
        data: values_cited,
        backgroundColor: ['#f56954', '#00a65a', '#f39c12', '#00c0ef', '#3c8dbc', '#d2d6de', '#ff5733', '#33ff57', '#5733ff', '#ff3366'],
    }]
};

var donutOptions_cited = {
    maintainAspectRatio: false,
    responsive: true,
};

// Create doughnut chart
var donutChart_cited = new Chart(donutChartCanvas_cited, {
    type: 'doughnut',
    data: donutData_cited,
    options: donutOptions_cited
});


// ===========================
var donutChartCanvas = $('#donutChart').get(0).getContext('2d');
var keys_citing = Object.keys(topCitingPatentsDict);
var values_citing = Object.values(topCitingPatentsDict);

var donutData_citing = {
    labels: keys_citing,
    datasets: [{
        data: values_citing,
        backgroundColor: ['#f56954', '#00a65a', '#f39c12', '#00c0ef', '#3c8dbc', '#d2d6de', '#ff5733', '#33ff57', '#5733ff', '#ff3366'],
    }]
};

var donutOptions_citing = {
    maintainAspectRatio: false,
    responsive: true,
};

// Create doughnut chart
var donutChart_citing = new Chart(donutChartCanvas, {
    type: 'doughnut',
    data: donutData_citing,
    options: donutOptions_citing
});
// ==============================================









    donutChartCanvas_cited.canvas.addEventListener('click', function(event) {
        var activeElements = donutChart_cited.getElementsAtEventForMode(event, 'index', {
            intersect: true
        });

        if (activeElements.length > 0) {
            var clickedIndex = activeElements[0].index;
            var clickX = event.clientX;
            var clickY = event.clientY;
            if (!tableVisible) {
                var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Patent</th><th>Citations</th></tr>';
                keys_cited.forEach(function(key, index) {
                    tableContent += '<tr><td>' + key + '</td><td>' + values_cited[index] + '</td></tr>';
                });
                tableContent += '</table>';
                var buttons = {
                    Ok: function() {
                        $(this).dialog('close');
                        tableVisible = false;
                    }
                };
                if ('download' in document.createElement('a')) {
                    buttons['Download'] = function() {
                        downloadExcelFile();
                    };
                }
                $('<div></div>').html(tableContent).dialog({
                    title: 'All Patents Details',
                    modal: true,
                    position: {
                        my: 'left top',
                        at: 'right top',
                        of: event,
                        collision: 'fit'
                    },
                    buttons: buttons,
                    close: function() {
                        tableVisible = false;
                    }
                });

                tableVisible = true;
            }
        }
    });


 function downloadExcelFile() {
    var user_id = window.user_id;
    fetch("/download_excel_file/", {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.blob();
    })
    .then(blob => {
        var link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = 'top_ten_cited_patents.xlsx';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(error => console.error('Error:', error));
}

    //-------------
    //- DONUT CHART -
    //-------------
    var donutChartCanvas = $('#donutChart').get(0).getContext('2d');
    var keys_citing = Object.keys(topCitingPatentsDict);
    var values_citing = Object.values(topCitingPatentsDict);

    var donutData_citing = {
        labels: keys_citing,
        datasets: [{
            data: values_citing,
            backgroundColor: ['#f56954', '#00a65a', '#f39c12', '#00c0ef', '#3c8dbc', '#d2d6de', '#ff5733', '#33ff57', '#5733ff', '#ff3366'],
        }]
    };

    var donutOptions_citing = {
        maintainAspectRatio: false,
        responsive: true,
    };

    // Create doughnut chart
    var donutChart_citing = new Chart(donutChartCanvas, {
        type: 'doughnut',
        data: donutData_citing,
        options: donutOptions_citing
    });

    donutChartCanvas.canvas.addEventListener('click', function(event) {
        var activeElements = donutChart_cited.getElementsAtEventForMode(event, 'index', {
            intersect: true
        });

        if (activeElements.length > 0) {
            var clickedIndex = activeElements[0].index;
            var clickX = event.clientX;
            var clickY = event.clientY;
            if (!tableVisible) {
                var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Patent</th><th>Citations</th></tr>';
                keys_citing.forEach(function(key, index) {
                    tableContent += '<tr><td>' + key + '</td><td>' + values_citing[index] + '</td></tr>';
                });
                tableContent += '</table>';
                var buttons = {
                    Ok: function() {
                        $(this).dialog('close');
                        tableVisible = false;
                    }
                };
                if ('download' in document.createElement('a')) {
                    buttons['Download'] = function() {
                        download_citedExcelFile();
                    };
                }
                $('<div></div>').html(tableContent).dialog({
                    title: 'All Patents Details',
                    modal: true,
                    position: {
                        my: 'left top',
                        at: 'right top',
                        of: event,
                        collision: 'fit'
                    },
                    buttons: buttons,
                    close: function() {
                        tableVisible = false;
                    }
                });

                tableVisible = true;
            }
        }
    });


    function download_citedExcelFile() {
    var user_id = window.user_id;
    fetch("/download_citing_excel_file/", {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        return response.blob();
    })
    .then(blob => {
        var link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = 'top_ten_citing_patents.xlsx';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(error => console.error('Error:', error));
}

    //-------------
    //- PIE CHART -
    //-------------
    var legalStatusCounts = window.legalStatusCounts;
    var pieChartCanvas = $('#pieChart').get(0).getContext('2d');
    var pieData = {
        labels: Object.keys(legalStatusCounts),
        datasets: [{
            data: Object.values(legalStatusCounts),
            backgroundColor: ['#f56954', '#00a65a', '#f39c12', '#00c0ef'],
        }],
    };

    var pieOptions = {
        maintainAspectRatio: false,
        responsive: true,
    };

    var pieChart = new Chart(pieChartCanvas, {
        type: 'pie',
        data: pieData,
        options: pieOptions,
    });
//  for table
   pieChartCanvas.canvas.addEventListener('click', function(event) {
        var activeElements = pieChart.getElementsAtEventForMode(event, 'index', {
            intersect: true
        });

        if (activeElements.length > 0) {
            var clickedIndex = activeElements[0].index;
            var clickX = event.clientX;
            var clickY = event.clientY;
            if (!tableVisible) {
                var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Status</th><th>Count</th><th>Action</th></tr>';
            
                Object.entries(legalStatusCounts).forEach(function ([status, count]) {
                    tableContent += '<tr>';
                    tableContent += '<td>' + status + '</td>';
                    tableContent += '<td>' + count + '</td>';
                    tableContent += '<td><button onclick="downloadAction(\'' + status + '\')">Download</button>';
                    tableContent += '<button onclick="viewAction(\'' + status + '\')">View</button></td>';
                    tableContent += '</tr>';
                });
            
                tableContent += '</table>';
            
                var buttons = {
                    Ok: function () {
                        $(this).dialog('close');
                        tableVisible = false;
                    }
                };
            
                $('<div></div>').html(tableContent).dialog({
                    title: 'All Patents Details',
                    modal: true,
                    position: {
                        my: 'left top',
                        at: 'right top',
                        of: event,
                        collision: 'fit'
                    },
                    buttons: buttons,
                    close: function () {
                        tableVisible = false;
                    }
                });
            
                tableVisible = true;
            }
            
            // Function to handle download action
            function downloadAction(status) {
                // Implement your download logic here
                console.log('Download action for status:', status);
            }
            
            // Function to handle view action
            function viewAction(status) {
                // Implement your view logic here
                console.log('View action for status:', status);
            }
            

        }
    });
//  for table
    //-------------
    //- BAR CHART -
    //-------------
    var topAssigneesData = window.topAssigneesData;
    var barChartCanvas = $('#barChart').get(0).getContext('2d');
    var barChartData = {
        labels: topAssigneesData.map(function(item) {
            return item['Assignee - Standardized'];
        }),
        datasets: [{
            label: 'Top Assignees',
            backgroundColor: 'rgba(60,141,188,0.9)',
            borderColor: 'rgba(60,141,188,0.8)',
            borderWidth: 1,
            data: topAssigneesData.map(function(item) {
                return item.count;
            }),
        }],
    };

    var stackedBarChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            xAxes: [{
                stacked: true,
            }],
            yAxes: [{
                stacked: true
            }]
        }
    }

    var barChart = new Chart(barChartCanvas, {
        type: 'bar',
        data: barChartData,
        options: stackedBarChartOptions,
    });


    //---------------------
    //- STACKED BAR CHART -
    //---------------------
    var topAssigneesDataStacked = window.topAssigneesDataStacked;
    var stackedBarChartCanvas = $('#stackedBarChart').get(0).getContext('2d')
    var stackedBarChartData = {
        labels: topAssigneesDataStacked.map(function(item) {
            return item['assignee_standardized'];
        }),
        datasets: [{
            label: 'Recent Active Assignees',
            backgroundColor: 'rgba(60,141,188,0.9)',
            borderColor: 'rgba(60,141,188,0.8)',
            borderWidth: 1,
            data: topAssigneesDataStacked.map(function(item) {
                return item.count;
            }),
        }],
    };

    var stackedBarChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            xAxes: [{
                stacked: true,
            }],
            yAxes: [{
                stacked: true
            }]
        }
    };

    var stackedBarChart = new Chart(stackedBarChartCanvas, {
        type: 'bar',
        data: stackedBarChartData,
        options: stackedBarChartOptions,
    });
    //  for table
   stackedBarChartCanvas.canvas.addEventListener('click', function(event) {
    var activeElements = stackedBarChart.getElementsAtEventForMode(event, 'index', {
        intersect: true
    });

    if (activeElements.length > 0) {
        var clickedIndex = activeElements[0].index;
        var clickX = event.clientX;
        var clickY = event.clientY;
        if (!tableVisible) {
            var tableContent = '<table style="background-color: #f9f9f9; color: #000;" border="1"><tr><th>Patent</th><th>Citations</th></tr>';

            tableContent += '<tr><td>' + 'dfgvdf' + '</td><td>' + 'dtgbtbhg' + '</td></tr>';

            tableContent += '</table>';
            var buttons = {
                Ok: function() {
                    $(this).dialog('close');
                    tableVisible = false;
                }
            };
            if ('download' in document.createElement('a')) {
                buttons['Download'] = function() {
                    download_citedExcelFile();
                };
            }
            $('<div></div>').html(tableContent).dialog({
                title: 'All Patents Details',
                modal: true,
                position: {
                    my: 'left top',
                    at: 'right top',
                    of: event,
                    collision: 'fit'
                },
                buttons: buttons,
                close: function() {
                    tableVisible = false;
                }
            });

            tableVisible = true;
        }
    }
});
//  for table

});



function changeChartType() {
    var selectedChartType = $("#chartType").val()
    $("#" + selectedChartType + "Chart").show();
}
$(document).ready(function() {
    changeChartType();
});


