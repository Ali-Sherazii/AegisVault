import json, urllib.parse, joblib, os

class WafPredictor:
    def __init__(self, text_model_path: str):
        self.clf = joblib.load(text_model_path)
        # expose model path and name for diagnostics
        self.model_path = text_model_path
        try:
            self.model_name = os.path.basename(text_model_path)
        except Exception:
            self.model_name = str(text_model_path)
        # Friendly display name mapping based on filename hints
        display_map = {
            'predictor_svc.joblib': 'Support Vector Machine',
            'predictor_rf.joblib': 'Random Forest',
            'predictor_lr.joblib': 'Logistic Regression',
        }
        self.model_display_name = display_map.get(self.model_name, self.model_name)

    def _unquote(self, text: str) -> str:
        k, prev = 0, text or ""
        while k < 100:
            nxt = urllib.parse.unquote_plus(prev)
            if nxt == prev:
                break
            prev = nxt
            k += 1
        return prev

    def _clean(self, s: str) -> str:
        s = self._unquote(s)
        s = s.strip().lower()
        return ' '.join(s.split())

    def predict_request(self, url_with_query: str, body_params: list[str], headers: dict) -> dict:
        # text model inputs
        text_params, locations = [], []
        if url_with_query:
            text_params.append(self._clean(url_with_query)); locations.append('Request')
        for b in body_params or []:
            if b:
                text_params.append(self._clean(str(b))); locations.append('Body')
        if headers.get('Cookie'):
            text_params.append(self._clean(headers['Cookie'])); locations.append('Cookie')
        if headers.get('User-Agent'):
            text_params.append(self._clean(headers['User-Agent'])); locations.append('User Agent')
        if headers.get('Accept-Encoding'):
            text_params.append(self._clean(headers['Accept-Encoding'])); locations.append('Accept Encoding')
        if headers.get('Accept-Language'):
            text_params.append(self._clean(headers['Accept-Language'])); locations.append('Accept Language')

        threats = {}
        confidence_scores = {}
        
        if text_params:
            # Use predict_proba instead of predict for probability scores
            try:
                probas = self.clf.predict_proba(text_params)
                preds = self.clf.predict(text_params)
                
                for i, (pred, proba) in enumerate(zip(preds, probas)):
                    if pred != 'valid':
                        threats[pred] = locations[i]
                        # Get confidence for the predicted class
                        pred_idx = list(self.clf.classes_).index(pred)
                        confidence_scores[pred] = proba[pred_idx]
            except AttributeError:
                # Fallback to binary prediction if predict_proba not available
                preds = self.clf.predict(text_params)
                for i, p in enumerate(preds):
                    if p != 'valid':
                        threats[p] = locations[i]
                        confidence_scores[p] = 0.8  # Default confidence for binary models

        if not threats:
            threats['valid'] = ''
            confidence_scores['valid'] = 1.0
            
        return threats, confidence_scores