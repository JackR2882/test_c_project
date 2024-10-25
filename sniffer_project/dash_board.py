from dash import Dash, html, dcc, callback, Output, Input
import plotly.express as px
import pandas as pd

df = pd.read_csv('https://raw.githubusercontent.com/plotly/datasets/master/gapminder_unfiltered.csv')

df = pd.read_csv('data/network_stats.csv')


print(df)


app = Dash()

app.layout = [
    html.H1(children='Network stats', style={'textAlign':'center'}),
    dcc.Dropdown(df.Protocol.unique(), 'TCP', id='dropdown-selection'),
    dcc.Graph(id='graph-content')
]

@callback(
    Output('graph-content', 'figure'),
    Input('dropdown-selection', 'value')
)
def update_graph(value):
    dff = df[df.Protocol==value]
    return px.line(df, x='Src Port', y='Src Port')


if __name__ == '__main__':
    app.run(debug=True)