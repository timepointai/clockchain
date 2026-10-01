import unittest
import graphview


class GraphTests(unittest.TestCase):
    def test_same_year_chain_uses_edge_direction_not_title_order(self):
        nodes = {n: {'year':1970,'name':n,'unknown':False} for n in ('a','b','c')}
        svg, order = graphview.svg_component(list(nodes), nodes, [('c','a',2,1),('a','b',2,1)], 0)
        self.assertEqual(order, ['c','a','b'])
        self.assertIn('causation', svg)
